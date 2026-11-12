(function () {
    'use strict';

    var API = '/api/auth/';
    var DOMAIN_ERROR = 'Only @baltijosgimnazija.lt email addresses are allowed.';
    var steps = ['step-credentials', 'code-form', 'forgot-form', 'reset-form'];

    var mode = 'login';
    var pendingEmail = '';

    function $(id) { return document.getElementById(id); }
    function say(text) { $('message').textContent = text || ''; }
    function isSchoolEmail(email) { return /@baltijosgimnazija\.lt$/.test(email); }

    function show(step) {
        steps.forEach(function (id) { $(id).hidden = id !== step; });
        say('');
    }

    function setMode(m) {
        mode = m;
        $('password').autocomplete = m === 'signup' ? 'new-password' : 'current-password';
        $('mode-login').disabled = m === 'login';
        $('mode-signup').disabled = m === 'signup';
        $('forgot-row').hidden = m !== 'login';
        say('');
    }

    async function api(path, body) {
        var res = await fetch(API + path, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify(body || {})
        });
        var data = {};
        try { data = await res.json(); } catch (e) { /* non-JSON response */ }
        if (!res.ok) throw new Error(data.error || 'Request failed.');
        return data;
    }

    async function showDone() {
        var res = await fetch(API + 'me', { credentials: 'same-origin' });
        if (!res.ok) return false;
        var me = await res.json();
        $('who').textContent = me.email;
        $('auth').hidden = true;
        $('done').hidden = false;
        return true;
    }

    $('mode-login').addEventListener('click', function () { setMode('login'); });
    $('mode-signup').addEventListener('click', function () { setMode('signup'); });

    // Log in / sign up
    $('credentials-form').addEventListener('submit', async function (e) {
        e.preventDefault();
        say('');
        var email = $('email').value.trim().toLowerCase();
        if (!isSchoolEmail(email)) { say(DOMAIN_ERROR); return; }

        $('continue').disabled = true;
        try {
            var data = await api(mode, { email: email, password: $('password').value });
            pendingEmail = email;
            if (data.next === 'verify') { show('code-form'); $('code').focus(); }
            else await showDone();
        } catch (err) {
            say(err.message);
        } finally {
            $('continue').disabled = false;
        }
    });

    // Email verification
    $('code-form').addEventListener('submit', async function (e) {
        e.preventDefault();
        say('');
        try {
            await api('verify', { email: pendingEmail, code: $('code').value });
            await showDone();
        } catch (err) { say(err.message); }
    });
    $('resend').addEventListener('click', async function () {
        try {
            await api('resend', { email: pendingEmail });
            say('If a code can be sent, it is on its way. You can request one per minute.');
        } catch (err) { say(err.message); }
    });

    // Password reset
    $('forgot').addEventListener('click', function () {
        $('forgot-email').value = $('email').value;
        show('forgot-form');
        $('forgot-email').focus();
    });
    $('forgot-form').addEventListener('submit', async function (e) {
        e.preventDefault();
        say('');
        var email = $('forgot-email').value.trim().toLowerCase();
        if (!isSchoolEmail(email)) { say(DOMAIN_ERROR); return; }
        try {
            await api('forgot', { email: email });
            pendingEmail = email;
            show('reset-form');
            say('If an account exists for that email, a code has been sent.');
            $('reset-code').focus();
        } catch (err) { say(err.message); }
    });
    $('reset-form').addEventListener('submit', async function (e) {
        e.preventDefault();
        say('');
        try {
            await api('reset', { email: pendingEmail, code: $('reset-code').value, newPassword: $('new-password').value });
            $('reset-code').value = '';
            $('new-password').value = '';
            $('password').value = '';
            $('email').value = pendingEmail;
            setMode('login');
            show('step-credentials');
            say('Password changed. Please log in with your new password.');
        } catch (err) { say(err.message); }
    });
    $('reset-resend').addEventListener('click', async function () {
        try {
            await api('forgot', { email: pendingEmail });
            say('If an account exists for that email, a code has been sent. You can request one per minute.');
        } catch (err) { say(err.message); }
    });
    Array.prototype.forEach.call(document.querySelectorAll('.back'), function (b) {
        b.addEventListener('click', function () { show('step-credentials'); });
    });

    $('logout').addEventListener('click', async function () {
        try { await api('logout'); } catch (e) { /* ignore */ }
        location.reload();
    });

    setMode('login');
    show('step-credentials');
    showDone();
})();
