import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import crypto from 'crypto';
import compression from 'compression';
import helmet from 'helmet';
import dotenv from 'dotenv';
// Choose database: SQLite or PostgreSQL (PostgreSQL is default for production)
const USE_POSTGRESQL = process.env.USE_POSTGRESQL === 'true';

let users, services, trades, withdrawals, balances, reviews, messages, disputeMessages;

if (USE_POSTGRESQL) {
  const db = await import('./database-postgres.js');
  users = db.users;
  services = db.services;
  trades = db.trades;
  withdrawals = db.withdrawals;
  balances = db.balances;
  reviews = db.reviews;
  messages = db.messages;
  disputeMessages = db.disputeMessages;
  
  // Initialize PostgreSQL database
  await db.initDatabase();
  console.log('🐘 Using PostgreSQL database');
} else {
  const db = await import('./database.js');
  users = db.users;
  services = db.services;
  trades = db.trades;
  withdrawals = db.withdrawals;
  balances = db.balances;
  reviews = db.reviews;
  console.log('📁 Using SQLite database');
}

dotenv.config();

const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = process.env.PORT || 8080;

// Production security and performance middleware
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// Compression middleware
app.use(compression({
    level: 6,
    threshold: 1024,
    filter: (req, res) => {
        if (req.headers['x-no-compression']) {
            return false;
        }
        return compression.filter(req, res);
    }
}));

// Body parsing middleware with limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting middleware
const rateLimit = (windowMs = 15 * 60 * 1000, max = 100) => {
    const requests = new Map();
    return (req, res, next) => {
        const ip = req.ip || req.connection.remoteAddress;
        const now = Date.now();
        const windowStart = now - windowMs;
        
        // Clean old requests
        for (const [timestamp] of requests) {
            if (timestamp < windowStart) {
                requests.delete(timestamp);
            }
        }
        
        // Count requests from this IP
        const ipRequests = Array.from(requests.values())
            .filter(req => req.ip === ip && req.timestamp > windowStart);
        
        if (ipRequests.length >= max) {
            return res.status(429).json({ 
                ok: false, 
                error: 'Too many requests, please try again later.' 
            });
        }
        
        requests.set(now, { ip, timestamp: now });
        next();
    };
};

// Apply rate limiting
app.use(rateLimit(15 * 60 * 1000, 100)); // 100 requests per 15 minutes

// Production logging middleware
const logger = (req, res, next) => {
    const start = Date.now();
    const originalSend = res.send;
    
    res.send = function(data) {
        const duration = Date.now() - start;
        const logData = {
            method: req.method,
            url: req.url,
            status: res.statusCode,
            duration: `${duration}ms`,
            ip: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent'),
            timestamp: new Date().toISOString()
        };
        
        if (process.env.NODE_ENV === 'production') {
            console.log(JSON.stringify(logData));
        } else {
            console.log(`${logData.method} ${logData.url} ${logData.status} - ${logData.duration}`);
        }
        
        originalSend.call(this, data);
    };
    
    next();
};

app.use(logger);

// Global error handler
app.use((err, req, res, next) => {
    console.error('Error:', err);
    
    if (process.env.NODE_ENV === 'production') {
        res.status(500).json({ 
            ok: false, 
            error: 'Internal server error' 
        });
    } else {
        res.status(500).json({ 
            ok: false, 
            error: err.message,
            stack: err.stack
        });
    }
});

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

// Database-backed storage (persistent across restarts)

app.get('/api/users', (_req, res) => {
    try {
        const allUsers = users.getAll();
        return res.json({ ok: true, users: allUsers });
    } catch (e) {
        return res.status(500).json({ ok: false, error: 'Failed to fetch users' });
    }
});

app.post('/api/users/upsert', (req, res) => {
    try {
        const { user } = req.body || {};
        if (!user || !user.id) {
            return res.status(400).json({ ok: false, error: 'Invalid user payload' });
        }
        const upsertedUser = users.upsert(user);
        return res.json({ ok: true, user: upsertedUser });
    } catch (e) {
        return res.status(500).json({ ok: false, error: 'Failed to upsert user' });
    }
});

app.post('/api/users/moderate', (req, res) => {
    try {
        const { userId, banned, verified } = req.body || {};
        if (!userId) return res.status(400).json({ ok: false, error: 'Missing userId' });
        const updatedUser = users.updateModeration(userId, { banned, verified });
        if (!updatedUser) return res.status(404).json({ ok: false, error: 'User not found' });
        return res.json({ ok: true, user: updatedUser });
    } catch (e) {
        return res.status(500).json({ ok: false, error: 'Failed to update user' });
    }
});

// Aggregate services across users
app.get('/api/services', (_req, res) => {
    try {
        const allServices = services.getAll();
        return res.json({ ok: true, services: allServices });
    } catch (e) {
        return res.status(500).json({ ok: false, error: 'Failed to fetch services' });
    }
});

app.post('/api/services/moderate', (req, res) => {
    try {
        const { serviceId, userId, approved } = req.body || {};
        if (!serviceId || !userId) return res.status(400).json({ ok: false, error: 'Missing identifiers' });
        const updatedService = services.updateApproval(serviceId, userId, Boolean(approved));
        if (!updatedService) return res.status(404).json({ ok: false, error: 'Service not found' });
        return res.json({ ok: true, service: updatedService });
    } catch (e) {
        return res.status(500).json({ ok: false, error: 'Failed to moderate service' });
    }
});

// ---- Balances: compute from completed trades minus approved withdrawals
app.get('/api/balances/:userId', (req, res) => {
    try {
        const userId = String(req.params.userId);
        const userBalances = balances.getByUserId(userId);
        return res.json({ ok: true, balances: userBalances });
    } catch (e) {
        return res.status(500).json({ ok: false, error: 'Failed to get balances' });
    }
});

// ---- Trades
app.post('/api/trades', (req, res) => {
    try {
        const { id, buyer_id, seller_id, service_id, amount, currency, description } = req.body || {};
        if (!id || !buyer_id || !seller_id || !amount || !currency) {
            return res.status(400).json({ ok: false, error: 'Missing required fields' });
        }
        const tradeData = { id, buyer_id, seller_id, service_id, amount: Number(amount), currency, description };
        const createdTrade = trades.create(tradeData);
        return res.json({ ok: true, trade: createdTrade });
    } catch (e) {
        return res.status(500).json({ ok: false, error: 'Failed to create trade' });
    }
});

app.put('/api/trades/:id/status', (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body || {};
        if (!status) return res.status(400).json({ ok: false, error: 'Missing status' });
        const updatedTrade = trades.updateStatus(id, status);
        if (!updatedTrade) return res.status(404).json({ ok: false, error: 'Trade not found' });
        return res.json({ ok: true, trade: updatedTrade });
    } catch (e) {
        return res.status(500).json({ ok: false, error: 'Failed to update trade status' });
    }
});

app.get('/api/trades/user/:userId', (req, res) => {
    try {
        const userId = req.params.userId;
        const userTrades = trades.getByUserId(userId);
        return res.json({ ok: true, trades: userTrades });
    } catch (e) {
        return res.status(500).json({ ok: false, error: 'Failed to fetch user trades' });
    }
});

// ---- Services management
app.post('/api/services', (req, res) => {
    try {
        const { id, user_id, title, description, price, currency, category } = req.body || {};
        if (!id || !user_id || !title || !price || !currency) {
            return res.status(400).json({ ok: false, error: 'Missing required fields' });
        }
        const serviceData = { id, user_id, title, description, price: Number(price), currency, category };
        const createdService = services.create(serviceData);
        return res.json({ ok: true, service: createdService });
    } catch (e) {
        return res.status(500).json({ ok: false, error: 'Failed to create service' });
    }
});

app.get('/api/services/user/:userId', (req, res) => {
    try {
        const userId = req.params.userId;
        const userServices = services.getByUserId(userId);
        return res.json({ ok: true, services: userServices });
    } catch (e) {
        return res.status(500).json({ ok: false, error: 'Failed to fetch user services' });
    }
});

// ---- Withdrawals
app.post('/api/withdrawals/request', (req, res) => {
    try {
        const { userId, amount, currency, address } = req.body || {};
        if (!userId || !amount || !currency || !address) return res.status(400).json({ ok: false, error: 'Missing fields' });
        const id = `wd_${Date.now()}`;
        const withdrawalData = { id, user_id: String(userId), amount: Number(amount), currency, address };
        const createdWithdrawal = withdrawals.create(withdrawalData);
        return res.json({ ok: true, withdrawal: createdWithdrawal });
    } catch (e) {
        return res.status(500).json({ ok: false, error: 'Failed to create withdrawal' });
    }
});

app.get('/api/withdrawals', (_req, res) => {
    try {
        const allWithdrawals = withdrawals.getAll();
        return res.json({ ok: true, withdrawals: allWithdrawals });
    } catch (e) {
        return res.status(500).json({ ok: false, error: 'Failed to list withdrawals' });
    }
});

app.post('/api/withdrawals/approve', (req, res) => {
    try {
        const { id, txId } = req.body || {};
        const updatedWithdrawal = withdrawals.updateStatus(id, 'APPROVED', txId);
        if (!updatedWithdrawal) return res.status(404).json({ ok: false, error: 'Withdrawal not found' });
        return res.json({ ok: true, withdrawal: updatedWithdrawal });
    } catch (e) {
        return res.status(500).json({ ok: false, error: 'Failed to approve withdrawal' });
    }
});

app.post('/api/withdrawals/reject', (req, res) => {
    try {
        const { id, reason } = req.body || {};
        const updatedWithdrawal = withdrawals.updateStatus(id, 'REJECTED', null, reason);
        if (!updatedWithdrawal) return res.status(404).json({ ok: false, error: 'Withdrawal not found' });
        return res.json({ ok: true, withdrawal: updatedWithdrawal });
    } catch (e) {
        return res.status(500).json({ ok: false, error: 'Failed to reject withdrawal' });
    }
});

// Admin Analytics Endpoints
app.get('/api/admin/stats', (_req, res) => {
    try {
        const allUsers = users.getAll();
        const allTrades = trades.getAll();
        const allWithdrawals = withdrawals.getAll();
        
        const stats = {
            totalUsers: allUsers.length,
            verifiedUsers: allUsers.filter(u => u.is_verified).length,
            bannedUsers: allUsers.filter(u => u.is_banned).length,
            totalTrades: allTrades.length,
            completedTrades: allTrades.filter(t => t.status === 'COMPLETED').length,
            activeTrades: allTrades.filter(t => !['COMPLETED', 'CANCELLED'].includes(t.status)).length,
            disputedTrades: allTrades.filter(t => t.status === 'DISPUTE').length,
            totalVolume: allTrades.filter(t => t.status === 'COMPLETED').reduce((sum, t) => sum + t.amount, 0),
            pendingWithdrawals: allWithdrawals.filter(w => w.status === 'PENDING').length,
            totalWithdrawals: allWithdrawals.length
        };
        
        return res.json({ ok: true, stats });
    } catch (e) {
        return res.status(500).json({ ok: false, error: 'Failed to fetch stats' });
    }
});

// Enhanced Services with approval status
app.get('/api/admin/services', (_req, res) => {
    try {
        const allServices = services.getAll();
        return res.json({ ok: true, services: allServices });
    } catch (e) {
        return res.status(500).json({ ok: false, error: 'Failed to fetch services' });
    }
});

// Enhanced Users with detailed info
app.get('/api/admin/users', (_req, res) => {
    try {
        const allUsers = users.getAll();
        return res.json({ ok: true, users: allUsers });
    } catch (e) {
        return res.status(500).json({ ok: false, error: 'Failed to fetch users' });
    }
});

// User moderation endpoint
app.post('/api/users/moderate', (req, res) => {
    try {
        const { userId, banned, verified } = req.body || {};
        const updatedUser = users.updateModeration(userId, { banned, verified });
        if (!updatedUser) return res.status(404).json({ ok: false, error: 'User not found' });
        return res.json({ ok: true, user: updatedUser });
    } catch (e) {
        return res.status(500).json({ ok: false, error: 'Failed to moderate user' });
    }
});

// Service moderation endpoint
app.post('/api/services/moderate', (req, res) => {
    try {
        const { serviceId, userId, approved } = req.body || {};
        const updatedService = services.updateApproval(serviceId, userId, approved);
        if (!updatedService) return res.status(404).json({ ok: false, error: 'Service not found' });
        return res.json({ ok: true, service: updatedService });
    } catch (e) {
        return res.status(500).json({ ok: false, error: 'Failed to moderate service' });
    }
});

// Health endpoint for platform checks
app.get('/health', (_req, res) => res.json({ ok: true }));

// Optional: serve static frontend only if present and enabled
const distPath = path.resolve(__dirname, 'dist');
const serveStatic = process.env.SERVE_STATIC === 'true' && fs.existsSync(path.join(distPath, 'index.html'));
if (serveStatic) {
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
        res.sendFile(path.resolve(distPath, 'index.html'));
    });
}

// 404 handler (must be last)
app.use((req, res) => {
    res.status(404).json({ 
        ok: false, 
        error: 'Endpoint not found' 
    });
});

app.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`Server running on http://localhost:${PORT}`);
});


