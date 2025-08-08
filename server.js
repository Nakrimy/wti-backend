// server.js
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-super-secret';
const DB_FILE = process.env.SQLITE_FILE || 'wti.db';
const FRONTEND_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:8080';

const DB = new Database(DB_FILE);

// --- DB init ---
DB.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  passhash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

// --- Middleware ---
app.set('trust proxy', 1); // needed for secure cookies on Render
app.use(cors({
  origin: FRONTEND_ORIGIN,
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());

// --- Helpers ---
const normEmail = (e) => String(e || '').trim().toLowerCase();
function setAuthCookie(res, token) {
  res.cookie('wti_jwt', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: true, // must be true for HTTPS
    maxAge: 1000 * 60 * 60 * 24 * 7,
    path: '/',
  });
}
function authMiddleware(req, _res, next) {
  const token = req.cookies?.wti_jwt;
  if (!token) return next();
  try {
    req.user = jwt.verify(token, JWT_SECRET);
  } catch {}
  next();
}
app.use(authMiddleware);

// --- Routes ---
app.get('/healthz', (_req, res) => res.json({ ok: true }));

app.post('/api/auth/register', async (req, res) => {
  try {
    let { email, password } = req.body || {};
    email = normEmail(email);
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const exists = DB.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (exists) return res.status(409).json({ error: 'Email already registered' });

    const passhash = await bcrypt.hash(password, 10);
    const info = DB.prepare('INSERT INTO users (email, passhash) VALUES (?, ?)').run(email, passhash);
    const user = { id: info.lastInsertRowid, email };

    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });
    setAuthCookie(res, token);
    res.json({ ok: true, user });
  } catch (e) {
    console.error('[REGISTER] error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    let { email, password } = req.body || {};
    email = normEmail(email);
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const row = DB.prepare('SELECT id, email, passhash FROM users WHERE email = ?').get(email);
    if (!row) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, row.passhash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const user = { id: row.id, email: row.email };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });
    setAuthCookie(res, token);
    res.json({ ok: true, user });
  } catch (e) {
    console.error('[LOGIN] error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('wti_jwt', { path: '/' });
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  res.json({ user: req.user });
});

app.listen(PORT, () => {
  console.log(`✅ WTI backend running on port ${PORT}`);
  console.log(`CORS allowed origin: ${FRONTEND_ORIGIN}`);
});
