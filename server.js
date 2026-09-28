const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const crypto = require('crypto');

const app = express();
const PORT = 3000;
const SECRET_KEY = "PSYCO_TOOL_2025_SUPER_SECRET_KEY_CHANGE_ME_12345678";
const ADMIN_IDS = ['admin'];

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: 'psyco-panel-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

const db = new sqlite3.Database('./psyco.db');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tg_id TEXT UNIQUE,
        name TEXT,
        username TEXT,
        status TEXT DEFAULT 'pending',
        trials_used INTEGER DEFAULT 0,
        total_keys INTEGER DEFAULT 0,
        banned INTEGER DEFAULT 0,
        joined DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_value TEXT UNIQUE,
        hours INTEGER,
        status TEXT DEFAULT 'active',
        blocked INTEGER DEFAULT 0,
        user_tg_id TEXT,
        user_name TEXT,
        generated DATETIME DEFAULT CURRENT_TIMESTAMP,
        expiry DATETIME
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS broadcasts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT,
        sent_count INTEGER DEFAULT 0,
        created DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.get(`SELECT * FROM admins WHERE username = 'admin'`, (err, row) => {
        if (!row) {
            const hash = bcrypt.hashSync('admin123', 10);
            db.run(`INSERT INTO admins (username, password) VALUES (?, ?)`, ['admin', hash]);
            console.log('✅ Default admin: admin / admin123');
        }
    });
});

function requireAuth(req, res, next) {
    if (req.session.admin) return next();
    res.status(401).json({ error: 'Login required' });
}

// Generate key (same as your bot)
function generateLicenseKey(hours) {
    const expiryDt = new Date(Date.now() + hours * 3600 * 1000);
    const expiry = expiryDt.getFullYear().toString() +
        String(expiryDt.getMonth() + 1).padStart(2, '0') +
        String(expiryDt.getDate()).padStart(2, '0') +
        String(expiryDt.getHours()).padStart(2, '0');
    const timestamp = Math.floor(Date.now() / 1000);
    const salt = crypto.randomBytes(4).toString('hex').toUpperCase();
    const data = `ANY|${expiry}|${timestamp}|${salt}`;
    const sig = crypto.createHmac('sha256', SECRET_KEY).update(data).digest('hex').substring(0, 16).toUpperCase();
    const raw = `${data}|${sig}`;
    const b64 = Buffer.from(raw).toString('base64').replace(/=/g, '');
    const parts = b64.match(/.{1,8}/g) || [];
    return parts.join('-');
}

function formatDuration(hours) {
    const d = Math.floor(hours / 24);
    const h = hours % 24;
    if (d > 0 && h > 0) return `${d}d ${h}h`;
    if (d > 0) return d > 1 ? `${d} days` : `1 day`;
    return h > 1 ? `${h} hours` : `1 hour`;
}

// ===== AUTH =====
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM admins WHERE username = ?`, [username], (err, admin) => {
        if (!admin || !bcrypt.compareSync(password, admin.password)) {
            return res.status(401).json({ error: 'Galat credentials' });
        }
        req.session.admin = { id: admin.id, username: admin.username };
        res.json({ success: true });
    });
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/me', (req, res) => {
    res.json(req.session.admin || null);
});

// ===== DASHBOARD STATS =====
app.get('/api/stats', requireAuth, (req, res) => {
    db.get(`SELECT COUNT(*) as c FROM keys`, (e, total) => {
        db.get(`SELECT COUNT(*) as c FROM keys WHERE blocked = 0 AND expiry > datetime('now')`, (e, active) => {
            db.get(`SELECT COUNT(*) as c FROM keys WHERE blocked = 1`, (e, blocked) => {
                db.get(`SELECT COUNT(*) as c FROM keys WHERE expiry <= datetime('now') AND blocked = 0`, (e, expired) => {
                    db.get(`SELECT COUNT(*) as c FROM users`, (e, users) => {
                        db.get(`SELECT COUNT(*) as c FROM users WHERE status = 'approved'`, (e, approved) => {
                            db.get(`SELECT COUNT(*) as c FROM users WHERE status = 'pending'`, (e, pending) => {
                                db.get(`SELECT COUNT(*) as c FROM users WHERE banned = 1`, (e, banned) => {
                                    res.json({
                                        totalKeys: total.c,
                                        activeKeys: active.c,
                                        blockedKeys: blocked.c,
                                        expiredKeys: expired.c,
                                        totalUsers: users.c,
                                        approvedUsers: approved.c,
                                        pendingUsers: pending.c,
                                        bannedUsers: banned.c
                                    });
                                });
                            });
                        });
                    });
                });
            });
        });
    });
});

// ===== KEYS =====
app.get('/api/keys', requireAuth, (req, res) => {
    db.all(`SELECT * FROM keys ORDER BY id DESC`, (err, rows) => {
        res.json(rows || []);
    });
});

app.get('/api/keys/active', requireAuth, (req, res) => {
    db.all(`SELECT * FROM keys WHERE blocked = 0 AND expiry > datetime('now') ORDER BY expiry ASC`, (err, rows) => {
        res.json(rows || []);
    });
});

app.get('/api/keys/blocked', requireAuth, (req, res) => {
    db.all(`SELECT * FROM keys WHERE blocked = 1 ORDER BY id DESC`, (err, rows) => {
        res.json(rows || []);
    });
});

app.get('/api/keys/expiring', requireAuth, (req, res) => {
    db.all(`SELECT * FROM keys WHERE blocked = 0 AND expiry > datetime('now') AND expiry <= datetime('now', '+48 hours') ORDER BY expiry ASC`, (err, rows) => {
        res.json(rows || []);
    });
});

app.post('/api/keys/generate', requireAuth, (req, res) => {
    const { hours, user_tg_id, user_name } = req.body;
    if (!hours || hours < 1) return res.status(400).json({ error: 'Invalid duration' });
    const key = generateLicenseKey(hours);
    const expiry = new Date(Date.now() + hours * 3600 * 1000).toISOString();
    db.run(`INSERT INTO keys (key_value, hours, user_tg_id, user_name, expiry) VALUES (?, ?, ?, ?, ?)`,
        [key, hours, user_tg_id || null, user_name || 'Admin', expiry],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            if (user_tg_id) {
                db.run(`UPDATE users SET total_keys = total_keys + 1 WHERE tg_id = ?`, [user_tg_id]);
            }
            res.json({ success: true, key, id: this.lastID, expiry });
        });
});

app.post('/api/keys/:id/block', requireAuth, (req, res) => {
    db.run(`UPDATE keys SET blocked = 1 WHERE id = ?`, [req.params.id], function(err) {
        res.json({ success: true });
    });
});

app.post('/api/keys/:id/unblock', requireAuth, (req, res) => {
    db.run(`UPDATE keys SET blocked = 0 WHERE id = ?`, [req.params.id], function(err) {
        res.json({ success: true });
    });
});

app.delete('/api/keys/:id', requireAuth, (req, res) => {
    db.run(`DELETE FROM keys WHERE id = ?`, [req.params.id], function(err) {
        res.json({ success: true });
    });
});

app.delete('/api/keys', requireAuth, (req, res) => {
    db.run(`DELETE FROM keys`, function(err) {
        res.json({ success: true, deleted: this.changes });
    });
});

// ===== USERS =====
app.get('/api/users', requireAuth, (req, res) => {
    db.all(`SELECT * FROM users ORDER BY id DESC`, (err, rows) => {
        res.json(rows || []);
    });
});

app.get('/api/users/pending', requireAuth, (req, res) => {
    db.all(`SELECT * FROM users WHERE status = 'pending' AND banned = 0 ORDER BY id DESC`, (err, rows) => {
        res.json(rows || []);
    });
});

app.get('/api/users/approved', requireAuth, (req, res) => {
    db.all(`SELECT * FROM users WHERE status = 'approved' AND banned = 0 ORDER BY id DESC`, (err, rows) => {
        res.json(rows || []);
    });
});

app.get('/api/users/banned', requireAuth, (req, res) => {
    db.all(`SELECT * FROM users WHERE banned = 1 ORDER BY id DESC`, (err, rows) => {
        res.json(rows || []);
    });
});

app.post('/api/users/:id/approve', requireAuth, (req, res) => {
    db.run(`UPDATE users SET status = 'approved' WHERE id = ?`, [req.params.id], function(err) {
        res.json({ success: true });
    });
});

app.post('/api/users/:id/reject', requireAuth, (req, res) => {
    db.run(`DELETE FROM users WHERE id = ? AND status = 'pending'`, [req.params.id], function(err) {
        res.json({ success: true });
    });
});

app.post('/api/users/:id/unapprove', requireAuth, (req, res) => {
    db.run(`UPDATE users SET status = 'pending' WHERE id = ?`, [req.params.id], function(err) {
        res.json({ success: true });
    });
});

app.post('/api/users/:id/ban', requireAuth, (req, res) => {
    db.run(`UPDATE users SET banned = 1, status = 'pending' WHERE id = ?`, [req.params.id], function(err) {
        res.json({ success: true });
    });
});

app.post('/api/users/:id/unban', requireAuth, (req, res) => {
    db.run(`UPDATE users SET banned = 0 WHERE id = ?`, [req.params.id], function(err) {
        res.json({ success: true });
    });
});

app.post('/api/users/add', requireAuth, (req, res) => {
    const { tg_id, name, username } = req.body;
    db.run(`INSERT OR IGNORE INTO users (tg_id, name, username, status) VALUES (?, ?, ?, 'pending')`,
        [tg_id, name, username],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        });
});

// ===== SEARCH =====
app.get('/api/search', requireAuth, (req, res) => {
    const q = (req.query.q || '').toLowerCase();
    db.all(`SELECT * FROM users WHERE LOWER(tg_id) LIKE ? OR LOWER(name) LIKE ? OR LOWER(username) LIKE ?`,
        [`%${q}%`, `%${q}%`, `%${q}%`],
        (err, users) => {
            res.json(users || []);
        });
});

// ===== BROADCAST =====
app.post('/api/broadcast', requireAuth, (req, res) => {
    const { message } = req.body;
    db.run(`INSERT INTO broadcasts (message) VALUES (?)`, [message], function(err) {
        res.json({ success: true, id: this.lastID });
    });
});

app.get('/api/broadcasts', requireAuth, (req, res) => {
    db.all(`SELECT * FROM broadcasts ORDER BY id DESC`, (err, rows) => {
        res.json(rows || []);
    });
});

// ===== CHANGE PASSWORD =====
app.post('/api/change-password', requireAuth, (req, res) => {
    const { oldPass, newPass } = req.body;
    db.get(`SELECT * FROM admins WHERE username = ?`, [req.session.admin.username], (err, admin) => {
        if (!admin || !bcrypt.compareSync(oldPass, admin.password)) {
            return res.status(401).json({ error: 'Purana password galat hai' });
        }
        const hash = bcrypt.hashSync(newPass, 10);
        db.run(`UPDATE admins SET password = ? WHERE id = ?`, [hash, admin.id]);
        res.json({ success: true });
    });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 PSYCO PANEL: http://localhost:${PORT}`);
    console.log(`👤 Login: admin / admin123`);
});
