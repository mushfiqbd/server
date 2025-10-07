import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import crypto from 'crypto';
import compression from 'compression';
import helmet from 'helmet';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = process.env.PORT || 8080;

app.use(helmet({
    contentSecurityPolicy: false,
}));
app.use(compression());
app.use(express.json());

// Basic CORS for frontend domains (Netlify/Telegram webview)
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
});

// Verify Telegram initData per https://core.telegram.org/bots/webapps#validating-data-received-via-the-web-app
function getTelegramSecretKey(botToken) {
    return crypto.createHash('sha256').update(botToken).digest();
}

function parseInitData(initData) {
    return Object.fromEntries(new URLSearchParams(initData));
}

function isRecent(authDate) {
    const now = Math.floor(Date.now() / 1000);
    const FIVE_MIN = 5 * 60;
    return Math.abs(now - Number(authDate)) <= FIVE_MIN;
}

function verifyTelegramInitData(initData, botToken) {
    if (!initData || !botToken) return { ok: false, reason: 'Missing initData or bot token' };

    const data = parseInitData(initData);
    const hash = data.hash;
    if (!hash) return { ok: false, reason: 'Missing hash' };

    // Remove hash before checking
    const entries = Object.entries(data)
        .filter(([key]) => key !== 'hash')
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => `${k}=${v}`)
        .join('\n');

    const secret = getTelegramSecretKey(botToken);
    const calculatedHash = crypto
        .createHmac('sha256', secret)
        .update(entries)
        .digest('hex');

    if (calculatedHash !== hash) return { ok: false, reason: 'Hash mismatch' };

    if (!isRecent(data.auth_date)) return { ok: false, reason: 'Auth too old' };

    return { ok: true, data };
}

app.post('/api/verify', (req, res) => {
    try {
        const { initData } = req.body || {};
        const botToken = process.env.BOT_TOKEN;
        const result = verifyTelegramInitData(initData, botToken);
        if (!result.ok) {
            return res.status(401).json({ ok: false, error: result.reason });
        }

        // user is a JSON object in initData (URL-encoded)
        let user = {};
        try {
            user = JSON.parse(result.data.user);
        } catch (_) {}

        return res.json({ ok: true, user });
    } catch (e) {
        return res.status(500).json({ ok: false, error: 'Server error' });
    }
});

// Optional: serve static frontend only if present and enabled
const distPath = path.resolve(__dirname, 'dist');
const serveStatic = process.env.SERVE_STATIC === 'true' && fs.existsSync(path.join(distPath, 'index.html'));
if (serveStatic) {
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
        res.sendFile(path.resolve(distPath, 'index.html'));
    });
} else {
    // Health endpoint for platform checks
    app.get('/health', (_req, res) => res.json({ ok: true }));
}

app.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`Server running on http://localhost:${PORT}`);
});


