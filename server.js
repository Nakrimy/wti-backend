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
const DB = new Database('wti.db', { fileMustExist: false });

// ---------------- DB INIT ----------------
DB.pragma('journal_mode = WAL');
DB.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  passhash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

// ---------------- MIDDLEWARE ----------------
// IMPORTANT: allow credentials + your frontend origin (http-server)
const FRONTEND_ORIGINS = [
  'http://127.0.0.1:8080',
  'http://localhost:8080',
];

app.use(cors({
  origin(origin, cb) {
    // During local dev, origin may be undefined (like curl/Postman) — allow it.
    if (!origin || FRONTEND_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error(`Origin not allowed: ${origin}`));
  },
  credentials: true,
}));

app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

// ---------------- HELPERS ----------------
const normEmail = (e) => String(e || '').trim().toLowerCase();

function setAuthCookie(res, token) {
  res.cookie('wti_jwt', token, {
    httpOnly: true,
    sameSite: 'lax',   // OK for cross-site nav within same top site
    secure: false,     // true ONLY behind HTTPS
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    path: '/',
  });
}

function authMiddleware(req, _res, next) {
  const token = req.cookies?.wti_jwt;
  if (!token) return next();
  try {
    req.user = jwt.verify(token, JWT_SECRET);
  } catch (e) {
    // bad/expired token -> ignore
  }
  next();
}
app.use(authMiddleware);

// Small helper to log full errors
function logError(tag, err) {
  console.error(`[${tag}]`, err && err.stack ? err.stack : err);
}

// ---------------- ROUTES ----------------
app.get('/', (_req, res) => res.send('✅ WTI Backend is running!'));

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    let { email, password } = req.body || {};
    email = normEmail(email);
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const exists = DB.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (exists) return res.status(409).json({ error: 'Email already registered' });

    const passhash = await bcrypt.hash(String(password), 10);
    const info = DB.prepare('INSERT INTO users (email, passhash) VALUES (?, ?)').run(email, passhash);

    // better-sqlite3 lastInsertRowid can be bigint-like — force to Number
    const user = { id: Number(info.lastInsertRowid), email };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });
    setAuthCookie(res, token);

    console.log('[REGISTER] ok:', email);
    res.json({ ok: true, user });
  } catch (e) {
    logError('REGISTER', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    let { email, password } = req.body || {};
    email = normEmail(email);
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const row = DB.prepare('SELECT id, email, passhash FROM users WHERE email = ?').get(email);
    if (!row) {
      console.warn('[LOGIN] unknown email:', email);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const ok = await bcrypt.compare(String(password), String(row.passhash));
    if (!ok) {
      console.warn('[LOGIN] bad password for:', email);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = { id: Number(row.id), email: row.email };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });
    setAuthCookie(res, token);

    console.log('[LOGIN] ok:', email);
    res.json({ ok: true, user });
  } catch (e) {
    logError('LOGIN', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Logout
app.post('/api/auth/logout', (_req, res) => {
  res.clearCookie('wti_jwt', { path: '/' });
  res.json({ ok: true });
});

// Current user
app.get('/api/me', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  res.json({ user: req.user });
});

// ---------------- START ----------------
app.listen(PORT, () => {
  console.log(`WTI backend running at http://localhost:${PORT}`);
  console.log(`CORS allowed origins: ${FRONTEND_ORIGINS.join(', ')}`);
});
