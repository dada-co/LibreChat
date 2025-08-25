// api/server/index.js
// Minimal auth + static serving server for Own Chat (Heroku-friendly, Node CJS)

require('dotenv').config();

const path = require('path');
const fs = require('fs');
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

// ---------- Config ----------
const PORT = process.env.PORT || 3000;
const ROOT = path.join(__dirname, '..', '..'); // repo root (adjust if your layout differs)

// Where your built frontend lives (Vite/React etc.)
const DIST_DIR = path.join(ROOT, 'client', 'dist');
// Optional public folder for static assets
const PUBLIC_DIR = path.join(ROOT, 'public');

// Optional: redirect to another origin after login or for / and /c/new
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || '';

// Auth secrets
const MAGIC_LINK_SECRET = process.env.MAGIC_LINK_SECRET || 'dev-magic';
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET || 'dev-access';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'dev-refresh';

// ---------- App setup ----------
app.set('trust proxy', 1);
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

// Tiny logger
function log(level, ...args) {
  const ts = new Date().toISOString();
  // eslint-disable-next-line no-console
  console[level](`${ts} ${level.padEnd(5)} :`, ...args);
}

// Helper: read user from access token in cookie Authorization bridge
function getUserFromRequest(req) {
  const token =
    (req.cookies && (req.cookies.jwt || req.cookies.accessToken || req.cookies.token)) ||
    (req.headers.authorization && req.headers.authorization.replace(/^Bearer\s+/i, ''));

  if (!token) return null;
  try {
    const payload = jwt.verify(token, ACCESS_TOKEN_SECRET);
    return {
      id: payload.sub,
      email: payload.email || 'demo1@no-mail.invalid',
      role: payload.role || 'user',
    };
  } catch {
    return null;
  }
}

// Bridge: set Authorization header from cookies for convenience
app.use((req, _res, next) => {
  const c = Object.keys(req.cookies || {});
  log('info', `[req] ${req.method} ${req.path} cookies: ${JSON.stringify(c)}`);
  if (req.cookies && (req.cookies.jwt || req.cookies.accessToken || req.cookies.token)) {
    req.headers.authorization = `Bearer ${
      req.cookies.jwt || req.cookies.accessToken || req.cookies.token
    }`;
    log('info', '[bridge] Authorization set from cookie');
  }
  next();
});

// ---------- API ----------
app.get('/api/config', (_req, res) => {
  res.json({
    app: 'own-chat',
    env: process.env.NODE_ENV || 'development',
  });
});

app.get('/api/banner', (_req, res) => {
  res.status(200).send(''); // empty: no banner
});

app.get('/api/user', (req, res) => {
  const user = getUserFromRequest(req);
  if (!user) return res.status(401).json({ error: 'unauthorized' });
  res.json(user);
});

// Refresh endpoint stub (you can extend with DB/allow-list if needed)
app.post('/api/auth/refresh', (req, res) => {
  // We don't actually refresh here for demo; just 302 back (kept to match logs)
  res.redirect(302, '/');
});

// ---------- Magic link flow ----------

// NOTE: ORDER MATTERS!
// 1) A simple signed page you can hit to verify you’re signed-in
app.get('/m/signed', (req, res) => {
  const user = getUserFromRequest(req);
  // Simple white page used in your earlier screenshot
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`
    <!doctype html>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Signed in</title>
    <div style="font-family: ui-sans-serif,system-ui; font-size: 48px; padding: 16px;">
      <b>Signed in ✔</b>
    </div>
    <script>console.log(${JSON.stringify({ user })});</script>
  `);
});

// 2) /m/:token — verifies the magic token and sets cookies, then redirects
app.get('/m/:token', (req, res) => {
  const { token } = req.params;
  log('info', '[magic] GET /m/:token hit param token');

  let payload;
  try {
    payload = jwt.verify(token, MAGIC_LINK_SECRET);
  } catch (e) {
    log('warn', `[magic] invalid token: ${e.message}`);
    return res.status(401).send('invalid_token');
  }

  log('info', '[magic] token verified', {
    aud: payload.aud,
    sub: payload.sub,
    iat: payload.iat,
    exp: payload.exp,
  });

  // Build short-lived access + longer refresh
  const access = jwt.sign(
    { sub: payload.sub, email: 'demo1@no-mail.invalid', role: 'user' },
    ACCESS_TOKEN_SECRET,
    { expiresIn: '1h' }
  );
  const refresh = jwt.sign({ sub: payload.sub }, REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

  log('info', '[magic] signed tokens { access: ****, refresh: **** }');

  // Cookies compatible with cross-site redirect if needed
  const common = {
    httpOnly: true,
    sameSite: 'None',
    secure: true,
    path: '/',
  };

  res.cookie('jwt', access, { ...common, maxAge: 3600 * 1000 });
  res.cookie('token', access, { ...common, maxAge: 3600 * 1000 });
  res.cookie('accessToken', access, { ...common, maxAge: 3600 * 1000 });
  res.cookie('refreshToken', refresh, { ...common, maxAge: 7 * 24 * 3600 * 1000 });

  log('info', '[magic] set cookies', {
    cookieNames: ['jwt', 'token', 'accessToken', 'refreshToken'],
    sameSite: 'None',
    secure: true,
  });

  // After signing set, go to /m/signed (safe on same origin)
  res.redirect(302, '/m/signed');
});

// ---------- Static UI serving ----------

function sendFrontend(req, res) {
  // If you set FRONTEND_ORIGIN, just redirect there (preserves path)
  if (FRONTEND_ORIGIN) {
    const url = new URL(req.originalUrl || '/', FRONTEND_ORIGIN);
    return res.redirect(302, url.toString());
  }

  // Serve client/dist if it exists
  if (fs.existsSync(DIST_DIR) && fs.existsSync(path.join(DIST_DIR, 'index.html'))) {
    return res.sendFile(path.join(DIST_DIR, 'index.html'));
  }

  // Serve public/index.html if present
  if (fs.existsSync(PUBLIC_DIR) && fs.existsSync(path.join(PUBLIC_DIR, 'index.html'))) {
    return res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
  }

  // Fallback placeholder (what you’re seeing now)
  const user = getUserFromRequest(req) || {
    id: '68a9bb16aa1ca26aef9e9524',
    email: 'demo1@no-mail.invalid',
    role: 'user',
  };

  res.set('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!doctype html>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Own Chat</title>
<style>
  body { font-family: ui-sans-serif, system-ui; margin: 0; padding: 24px; }
  h1 { font-size: 64px; line-height: 1; margin: 0 0 24px; }
  .muted { color: #444; font-size: 22px; margin-bottom: 24px; }
  pre { background: #f3f3f3; padding: 16px; border-radius: 12px; overflow:auto }
  a { color: #0b57d0; text-decoration: none; }
  a:hover { text-decoration: underline; }
</style>
<h1>Own Chat</h1>
<p class="muted">This is a minimal placeholder UI served by <code>api/server/index.js</code>.</p>
<p><a href="/m/signed">Test: signed page</a></p>
<pre>${JSON.stringify(user, null, 2)}</pre>
`);
}

// Static folders (served if present)
if (fs.existsSync(DIST_DIR)) {
  app.use(express.static(DIST_DIR, { maxAge: '1h' }));
}
if (fs.existsSync(PUBLIC_DIR)) {
  app.use(express.static(PUBLIC_DIR, { maxAge: '1h' }));
}

// App routes that should show your frontend (or redirect)
app.get('/', sendFrontend);
app.get('/login', sendFrontend);
app.get('/c/new', sendFrontend);

// ---------- Error handling ----------
app.use((err, _req, res, _next) => {
  log('error', 'Unhandled error:', err && err.message ? err.message : err);
  res.status(500).send('internal_error');
});

// ---------- Start ----------
app.listen(PORT, () => {
  log('info', `Server listening on :${PORT}`);
});
