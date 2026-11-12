'use strict';

const crypto = require('crypto');
const express = require('express');
const rateLimit = require('express-rate-limit');
const { db, q } = require('./db');
const { sendCodeEmail } = require('./mail');

// ---------- config ----------
const isProd = process.env.ENV === 'prod';
const SITE_ORIGIN = process.env.SITE_ORIGIN || '';
const ALLOWED_DOMAIN = 'baltijosgimnazija.lt';

if (!process.env.CODE_SECRET || process.env.CODE_SECRET.length < 32) {
    if (isProd) throw new Error('CODE_SECRET must be set (32+ random characters) when ENV=prod');
}
const SECRET = process.env.CODE_SECRET || 'dev-only-secret';

const CODE_TTL_MS = 10 * 60 * 1000;          // a code is valid for 10 minutes
const CODE_RESEND_COOLDOWN_MS = 60 * 1000;   // one code per minute per account
const CODE_MAX_ATTEMPTS = 5;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_FAILED_LOGINS = 10;
const LOCKOUT_MS = 15 * 60 * 1000;
const COOKIE_NAME = 'sid';

const ERR_LOGIN = 'Invalid email or password.';
const ERR_DOMAIN = 'Only @baltijosgimnazija.lt email addresses are allowed.';
const ERR_PASSWORD = 'Password must be 10 to 128 characters.';
const ERR_CODE = 'Invalid or expired code.';
const ERR_SERVER = 'Something went wrong.';

// ---------- helpers ----------
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const hmac = (s) => crypto.createHmac('sha256', SECRET).update(s).digest('hex');

function safeEqual(a, b) {
    const ba = Buffer.from(a);
    const bb = Buffer.from(b);
    return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

// Only name@baltijosgimnazija.lt is accepted (no subdomains, no lookalikes, no "+" aliases).
const EMAIL_RE = /^[a-z0-9._-]{1,64}@baltijosgimnazija\.lt$/;

function normalizeEmail(raw) {
    if (typeof raw !== 'string') return null;
    const email = raw.trim().toLowerCase();
    if (email.length > 254 || !EMAIL_RE.test(email)) return null;
    if (email.split('@')[1] !== ALLOWED_DOMAIN) return null;
    return email;
}

function validPassword(pw) {
    return typeof pw === 'string' && pw.length >= 10 && pw.length <= 128;
}

// Password hashing: scrypt (built into Node, no extra install), OWASP-recommended parameters.
const SCRYPT = { N: 65536, r: 8, p: 2, maxmem: 128 * 1024 * 1024 };

function hashPassword(password) {
    return new Promise((resolve, reject) => {
        const salt = crypto.randomBytes(16);
        crypto.scrypt(password, salt, 64, SCRYPT, (err, key) => {
            if (err) return reject(err);
            resolve(['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p, salt.toString('base64'), key.toString('base64')].join('$'));
        });
    });
}

function verifyPassword(password, stored) {
    return new Promise((resolve) => {
        try {
            const [scheme, N, r, p, saltB64, keyB64] = stored.split('$');
            if (scheme !== 'scrypt') return resolve(false);
            const expected = Buffer.from(keyB64, 'base64');
            const opts = { N: Number(N), r: Number(r), p: Number(p), maxmem: SCRYPT.maxmem };
            crypto.scrypt(password, Buffer.from(saltB64, 'base64'), expected.length, opts, (err, key) => {
                if (err) return resolve(false);
                resolve(crypto.timingSafeEqual(key, expected));
            });
        } catch (e) {
            resolve(false);
        }
    });
}

// Used so that "no such account" takes as long as "wrong password".
let DUMMY_HASH = null;
hashPassword('dummy-password-for-timing').then((h) => { DUMMY_HASH = h; });

// ---------- codes ----------
// Creates and emails a code unless one was sent less than a minute ago.
async function issueCode(user, purpose) {
    const now = Date.now();
    const existing = q.getCode.get(user.id, purpose);
    if (existing && now - existing.last_sent_at < CODE_RESEND_COOLDOWN_MS) return false;

    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    q.upsertCode.run(user.id, purpose, hmac(`${purpose}:${user.id}:${code}`), now + CODE_TTL_MS, now);

    try {
        await sendCodeEmail(user.email, code, purpose);
    } catch (err) {
        console.error('Failed to send email:', err.message);
    }
    return true;
}

// True only if the code is correct, unexpired and attempts are not used up.
function checkCode(user, purpose, code) {
    const row = q.getCode.get(user.id, purpose);
    if (!row || row.expires_at < Date.now() || row.attempts >= CODE_MAX_ATTEMPTS) return false;
    q.bumpAttempts.run(user.id, purpose);
    return safeEqual(row.code_hash, hmac(`${purpose}:${user.id}:${code}`));
}

// ---------- sessions ----------
function readCookie(req, name) {
    const header = req.headers.cookie || '';
    for (const part of header.split(';')) {
        const [k, ...v] = part.trim().split('=');
        if (k === name) return decodeURIComponent(v.join('='));
    }
    return null;
}

function createSession(res, userId) {
    const token = crypto.randomBytes(32).toString('base64url');
    q.insertSession.run(sha256(token), userId, Date.now() + SESSION_TTL_MS);
    res.cookie(COOKIE_NAME, token, {
        httpOnly: true,
        secure: isProd,
        sameSite: 'lax',
        maxAge: SESSION_TTL_MS,
        path: '/'
    });
}

// Use on any route that needs a logged-in user: server.get('/app', auth.requireAuth, handler)
// Sets req.user = { id, email }.
function requireAuth(req, res, next) {
    const token = readCookie(req, COOKIE_NAME);
    if (!token) return res.status(401).json({ error: 'Not logged in.' });

    const session = q.sessionByHash.get(sha256(token));
    if (!session || session.expires_at < Date.now()) return res.status(401).json({ error: 'Not logged in.' });

    const user = q.userById.get(session.user_id);
    if (!user) return res.status(401).json({ error: 'Not logged in.' });

    req.user = user;
    next();
}

const finishReset = db.transaction((userId, hash) => {
    q.setPassword.run(hash, userId);
    q.markVerified.run(userId);        // they proved they own the mailbox; also clears any lockout
    q.deleteCode.run(userId, 'reset');
    q.deleteUserSessions.run(userId);  // log out every existing session
});

// ---------- middleware ----------
// CSRF defence: state-changing requests must be JSON and come from our own origin.
function originCheck(req, res, next) {
    if (req.method === 'GET' || req.method === 'HEAD') return next();
    if (!req.is('application/json')) return res.status(415).json({ error: 'Unsupported media type.' });

    const origin = req.get('origin');
    if (!origin) {
        if (isProd) return res.status(403).json({ error: 'Bad origin.' });
        return next();
    }

    let ok = SITE_ORIGIN !== '' && origin === SITE_ORIGIN;
    if (!ok) {
        try { ok = new URL(origin).host === req.get('host'); } catch (e) { ok = false; }
    }
    if (!ok) return res.status(403).json({ error: 'Bad origin.' });
    next();
}

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    standardHeaders: 'draft-7',
    legacyHeaders: false
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'Too many attempts. Try again later.' }
});

// ---------- routes ----------
const router = express.Router();
router.use(apiLimiter);
router.use(originCheck);

// Sign up: creates an unverified account and emails a code.
router.post('/signup', authLimiter, async (req, res) => {
    try {
        const body = req.body || {};
        const email = normalizeEmail(body.email);
        if (!email) return res.status(400).json({ error: ERR_DOMAIN });
        if (!validPassword(body.password)) return res.status(400).json({ error: ERR_PASSWORD });

        const existing = q.userByEmail.get(email);
        if (existing && existing.verified) {
            // Same answer as a fresh signup, so account existence is not revealed.
            return res.json({ ok: true, next: 'verify' });
        }

        const hash = await hashPassword(body.password);
        let user = existing;
        if (existing) {
            q.setUnverifiedPassword.run(hash, existing.id);
        } else {
            const info = q.insertUser.run(email, hash, Date.now());
            user = { id: Number(info.lastInsertRowid), email };
        }

        await issueCode(user, 'verify');
        res.json({ ok: true, next: 'verify' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: ERR_SERVER });
    }
});

// Confirm the emailed code: marks the account verified and logs the user in.
router.post('/verify', authLimiter, (req, res) => {
    try {
        const body = req.body || {};
        const email = normalizeEmail(body.email);
        const code = typeof body.code === 'string' ? body.code.trim() : '';
        if (!email || !/^\d{6}$/.test(code)) return res.status(400).json({ error: ERR_CODE });

        const user = q.userByEmail.get(email);
        if (!user || !checkCode(user, 'verify', code)) return res.status(400).json({ error: ERR_CODE });

        q.deleteCode.run(user.id, 'verify');
        q.markVerified.run(user.id);
        createSession(res, user.id);
        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: ERR_SERVER });
    }
});

// Log in with email + password.
router.post('/login', authLimiter, async (req, res) => {
    try {
        const body = req.body || {};
        const email = normalizeEmail(body.email);
        const password = body.password;
        if (!email || typeof password !== 'string' || password.length > 128) {
            return res.status(401).json({ error: ERR_LOGIN });
        }

        const user = q.userByEmail.get(email);
        if (!user) {
            if (DUMMY_HASH) await verifyPassword(password, DUMMY_HASH);
            return res.status(401).json({ error: ERR_LOGIN });
        }

        if (user.locked_until > Date.now()) {
            return res.status(429).json({ error: 'Account temporarily locked. Try again later.' });
        }

        if (!(await verifyPassword(password, user.password_hash))) {
            q.loginFailed.run(MAX_FAILED_LOGINS, Date.now() + LOCKOUT_MS, user.id);
            return res.status(401).json({ error: ERR_LOGIN });
        }

        q.loginOk.run(user.id);

        if (!user.verified) {
            await issueCode(user, 'verify');
            return res.json({ ok: true, next: 'verify' });
        }

        createSession(res, user.id);
        res.json({ ok: true, next: 'done' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: ERR_SERVER });
    }
});

// Resend the verification code (always the same answer).
router.post('/resend', authLimiter, async (req, res) => {
    try {
        const email = normalizeEmail((req.body || {}).email);
        if (email) {
            const user = q.userByEmail.get(email);
            if (user && !user.verified) await issueCode(user, 'verify');
        }
        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: ERR_SERVER });
    }
});

// Password reset, step 1: email a code. Always answers the same, whether or not the account exists.
router.post('/forgot', authLimiter, (req, res) => {
    try {
        const email = normalizeEmail((req.body || {}).email);
        if (email) {
            const user = q.userByEmail.get(email);
            // Not awaited, so response time does not reveal whether the account exists.
            if (user) issueCode(user, 'reset').catch((err) => console.error(err));
        }
        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: ERR_SERVER });
    }
});

// Password reset, step 2: code + new password.
router.post('/reset', authLimiter, async (req, res) => {
    try {
        const body = req.body || {};
        const email = normalizeEmail(body.email);
        const code = typeof body.code === 'string' ? body.code.trim() : '';
        if (!email || !/^\d{6}$/.test(code)) return res.status(400).json({ error: ERR_CODE });
        if (!validPassword(body.newPassword)) return res.status(400).json({ error: ERR_PASSWORD });

        const user = q.userByEmail.get(email);
        if (!user || !checkCode(user, 'reset', code)) return res.status(400).json({ error: ERR_CODE });

        finishReset(user.id, await hashPassword(body.newPassword));
        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: ERR_SERVER });
    }
});

router.post('/logout', (req, res) => {
    const token = readCookie(req, COOKIE_NAME);
    if (token) q.deleteSession.run(sha256(token));
    res.clearCookie(COOKIE_NAME, { path: '/' });
    res.json({ ok: true });
});

router.get('/me', requireAuth, (req, res) => {
    res.json({ email: req.user.email });
});

module.exports = { router, requireAuth };
