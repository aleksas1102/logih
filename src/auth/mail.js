'use strict';

const nodemailer = require('nodemailer');

const isProd = process.env.ENV === 'prod';

let transporter = null;

if (process.env.SMTP_HOST) {
    transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT || 587),
        secure: Number(process.env.SMTP_PORT) === 465,
        auth: process.env.SMTP_USER
            ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
            : undefined
    });
} else if (isProd) {
    // Fail closed: without email, nobody could verify or reset anything.
    throw new Error('SMTP_HOST must be configured when ENV=prod');
}

// purpose: 'verify' | 'reset'
async function sendCodeEmail(email, code, purpose) {
    if (!transporter) {
        // Development only: print the code instead of emailing it.
        console.log(`${purpose} code for ${email}: ${code}`);
        return;
    }

    const reset = purpose === 'reset';

    await transporter.sendMail({
        from: process.env.MAIL_FROM,
        to: email,
        subject: reset ? 'Your password reset code' : 'Your verification code',
        text: reset
            ? `Your password reset code is: ${code}\n\nIt expires in 10 minutes. If you did not request this, ignore this email; your password has not changed.`
            : `Your verification code is: ${code}\n\nIt expires in 10 minutes. If you did not request this, ignore this email.`
    });
}

module.exports = { sendCodeEmail };
