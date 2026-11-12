'use strict';

const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

// Database file lives in /data (git-ignored). Override with DB_PATH in .env.
const dbPath = process.env.DB_PATH || path.join(__dirname, '..', '..', 'data', 'auth.sqlite');
fs.mkdirSync(path.dirname(dbPath), { recursive: true });

const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

-- One row per (user, purpose). purpose is 'verify' (email confirmation) or 'reset' (password reset).
CREATE TABLE IF NOT EXISTS codes (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_sent_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, purpose)
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);
`);

const q = {
    userByEmail: db.prepare('SELECT * FROM users WHERE email = ?'),
    userById: db.prepare('SELECT id, email FROM users WHERE id = ?'),
    insertUser: db.prepare('INSERT INTO users (email, password_hash, verified, created_at) VALUES (?, ?, 0, ?)'),
    setUnverifiedPassword: db.prepare('UPDATE users SET password_hash = ? WHERE id = ? AND verified = 0'),
    setPassword: db.prepare('UPDATE users SET password_hash = ? WHERE id = ?'),
    markVerified: db.prepare('UPDATE users SET verified = 1, failed_logins = 0, locked_until = 0 WHERE id = ?'),
    loginFailed: db.prepare(`UPDATE users SET failed_logins = failed_logins + 1,
        locked_until = CASE WHEN failed_logins + 1 >= ? THEN ? ELSE locked_until END WHERE id = ?`),
    loginOk: db.prepare('UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ?'),

    getCode: db.prepare('SELECT * FROM codes WHERE user_id = ? AND purpose = ?'),
    upsertCode: db.prepare(`INSERT INTO codes (user_id, purpose, code_hash, expires_at, attempts, last_sent_at)
        VALUES (?, ?, ?, ?, 0, ?)
        ON CONFLICT(user_id, purpose) DO UPDATE SET code_hash = excluded.code_hash,
        expires_at = excluded.expires_at, attempts = 0, last_sent_at = excluded.last_sent_at`),
    bumpAttempts: db.prepare('UPDATE codes SET attempts = attempts + 1 WHERE user_id = ? AND purpose = ?'),
    deleteCode: db.prepare('DELETE FROM codes WHERE user_id = ? AND purpose = ?'),

    insertSession: db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)'),
    sessionByHash: db.prepare('SELECT * FROM sessions WHERE token_hash = ?'),
    deleteSession: db.prepare('DELETE FROM sessions WHERE token_hash = ?'),
    deleteUserSessions: db.prepare('DELETE FROM sessions WHERE user_id = ?'),

    purgeSessions: db.prepare('DELETE FROM sessions WHERE expires_at < ?'),
    purgeCodes: db.prepare('DELETE FROM codes WHERE expires_at < ?'),
    purgeStaleUnverified: db.prepare('DELETE FROM users WHERE verified = 0 AND created_at < ?')
};

// Hourly cleanup: expired sessions/codes, and accounts never verified within 24h.
setInterval(() => {
    const now = Date.now();
    q.purgeSessions.run(now);
    q.purgeCodes.run(now);
    q.purgeStaleUnverified.run(now - 24 * 60 * 60 * 1000);
}, 60 * 60 * 1000).unref();

module.exports = { db, q };
