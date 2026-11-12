// Environment variables
const dotenv = require('dotenv').config();

const env = process.env.ENV || 'development';
const portUncertified = process.env.PORT_UNCERTIFIED;
const portCertified = process.env.PORT_CERTIFIED;

// Express
const server = require('express')();

// Middleware
const bodyparser = require('body-parser');
const helmet = require('helmet');

// Authentication (sign up, log in, email codes, password reset)
const auth = require('./auth/routes');

// Utility
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

function DateFormatting(date) {
    return date.toLocaleString('en-US', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    });
}

function HandleError(err) {
    // Print the error in the console
    console.log(err);

    // Get datetime string
    const date = DateFormatting(Date.now());

    // Format error
    const formattedError = date + ": " + err.toString();

    // Get error log file contents
    var errorLog = "";

    const fileDir = process.env.ERROR_LOG_FILE;
    if (fs.existsSync(fileDir))
        errorLog = fs.readFileSync(fileDir);

    // serverend to error log
    errorLog += "\n\n" + formattedError;

    // Write to error log file
    fs.writeFileSync("error.log", errorLog, err2 => { console.log(err2.toString()) });
}

function Sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

// Certification setup
function Certification() {
    // HTTPS certificate settings (TODO)
    const settings = {
        key: fs.readFileSync('/etc/letsencrypt/live/.../privkey.pem', 'utf8'),
        cert: fs.readFileSync('/etc/letsencrypt/live/.../cert.pem', 'utf8'),
        ca: fs.readFileSync('/etc/letsencrypt/live/.../chain.pem', 'utf8')
    };
}

// Middleware setup
function Middleware() {
    // Behind a reverse proxy (nginx, Cloudflare...) set TRUST_PROXY=1 so client IPs are correct
    if (process.env.TRUST_PROXY)
        server.set('trust proxy', Number(process.env.TRUST_PROXY) || process.env.TRUST_PROXY);

    // Security headers (CSP, etc.). 'upgrade-insecure-requests' is only wanted in production,
    // otherwise browsers try to load local http assets over https during development.
    server.disable('x-powered-by');
    server.use(helmet({
        contentSecurityPolicy: {
            directives: {
                ...helmet.contentSecurityPolicy.getDefaultDirectives(),
                'upgrade-insecure-requests': env === 'prod' ? [] : null
            }
        }
    }));

    // Body parser allows the server to parse JSON packets sent by users
    server.use(bodyparser.urlencoded({ extended: true }));
    server.use(bodyparser.json());

    // Authentication API: /api/auth/signup, verify, login, resend, forgot, reset, logout, me
    server.use('/api/auth', auth.router);
}

// Webpage routing
function Routing() {
    // Establish routes
    const routes = {
        '/': path.join(__dirname, "..", "public", "index.html"),
        '/main': path.join(__dirname, "..", "public", "index.html"),
        '/home': path.join(__dirname, "..", "public", "index.html"),
        '/index': path.join(__dirname, "..", "public", "index.html"),

        // Authentication page
        '/login': path.join(__dirname, "..", "public", "login.html"),
        '/auth.js': path.join(__dirname, "..", "public", "auth.js")
    }

    // Send files
    for (const key of Object.keys(routes)) {
        server.get(key, (req, res) => {
            return res.sendFile(routes[key]);
        });
    }

    // Default to 404 if page is not found
    server.get('/{*splat}', (req, res) => {
        return res.status(404).sendFile(path.join(__dirname, "..", "public", process.env.ERR404_PAGE));
    });
}

// HTTP/HTTPS server launching
function StartServer() {
    switch (env) {
        case "dev":
            // Run HTTP server
            server.listen(portUncertified, () => {
                console.log("Uncertified server running on " + portUncertified.toString());
            });

            break;

        case "prod":
            // Redirect HTTP -> HTTPS
            http.createServer((req, res) => {
                res.writeHead(301, { "Location": `https://${req.headers.host}${req.url}` });
                res.end();
            }).listen(80);

            // Run HTTPS server
            https.createServer(settings, server).listen(portCertified, () => {
                console.log("Certified server running on " + portCertified.toString());
            });

            break;

        default:
            console.log("Unknown environment type '" + env.toString() + "'");
            break;
    }
}

// Main runtime
async function Main() {
    console.log("Starting server...")

    // Manage errors and retries
    let retries = 0;
    while (retries < process.env.MAX_RETRIES) {
        try {
            // Run all setup functions
            //Certification();
            Middleware();
            Routing();

            // Start the HTTP/HTTPS server
            StartServer();

            // Exit server
            break;
        }
        catch (err) {
            // Catch error and restart
            HandleError(err);

            console.log("Server crashed due to uncaught exception, restarting in " + process.env.RESTART_DELAY.toString() + " second(s)");
            await Sleep(process.env.RESTART_DELAY * 1000);
        }
    }

    // Notify that the server experianced too many errors
    if (retries >= process.env.MAX_RETRIES) {
        HandleError("Server exceeded max retries (" + process.env.MAX_RETRIES.toString() + "), exiting...");
        await Sleep(process.env.RESTART_DELAY * 1000);
    }
}

// Execute the main function
Main();