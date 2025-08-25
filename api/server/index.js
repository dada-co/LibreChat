// api/server/index.js
// Minimal Express API + Magic-link auth + safe static fallbacks.
// npm i express cookie-parser jsonwebtoken bcryptjs

const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const app = express();

// --- Config & Secrets --------------------------------------------------------
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || '/';

const MAGIC_LINK_SECRET = process.env.MAGIC_LINK_SECRET || 'dev-magic-secret';
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET || 'dev-access-secret';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'dev-refresh-secret';

// --- Light logger ------------------------------------------------------------
const log = {
  info: (...a) => console.log(new Date().toISOString(), 'info :', ...a),
  warn: (...a) => console.warn(new Date().toISOString(), 'warn :', ...a),
  error: (...a) => console.error(new Date().toISOString(), 'error:', ...a),
};

// --- Express middleware ------------------------------------------------------
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.use((req, _res, next) => {
  log.info(`[req] ${req.method} ${req.path} cookies: ${JSON.stringify(Object.keys(req.cookies || {}))}`);
  next();
});

app.use((req, _res, next) => {
  if (req.path === '/api/auth/refresh') {
    log.info('[bridge] SKIP on /api/auth/refresh');
    return next();
  }
  const token = req.cookies?.jwt || req.cookies?.accessToken || req.cookies?.token;
  if (token && !req.headers.authorization) {
    req.headers.authorization = `Bearer ${token}`;
    log.info('[bridge] Authorization set from cookie');
  }
  next();
});

// --- Helpers -----------------------------------------------------------------
const cookieBase = {
  httpOnly: true,
  sameSite: 'None',
  secure: true,
  path: '/',
};

function signAccess(payload) {
  const claims = { sub: payload.sub, email: payload.email, role: payload.role || 'user' };
  return jwt.sign(claims, ACCESS_TOKEN_SECRET, { expiresIn: '2h' });
}
function signRefresh(payload) {
  const claims = { sub: payload.sub, typ: 'refresh' };
  return jwt.sign(claims, REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
}
function setAuthCookies(res, access, refresh) {
  res.cookie('jwt', access, cookieBase);
  res.cookie('token', access, cookieBase);
  res.cookie('accessToken', access, cookieBase);
  res.cookie('refreshToken', refresh, cookieBase);
}
function clearAuthCookies(res) {
  const opts = { ...cookieBase };
  res.clearCookie('jwt', opts);
  res.clearCookie('token', opts);
  res.clearCookie('accessToken', opts);
  res.clearCookie('refreshToken', opts);
}

// naive in-memory refresh ring
const REFRESH_HASHES = [];
function rememberRefresh(rt) {
  try {
    const hash = bcrypt.hashSync(rt, 10);
    const before = REFRESH_HASHES.length;
    REFRESH_HASHES.push(hash);
    while (REFRESH_HASHES.length > 5) REFRESH_HASHES.shift();
    const after = REFRESH_HASHES.length;
    log.info('[magic] saved refresh hash', { listLenBefore: before, listLenAfter: after, hash });
  } catch (e) {
    log.warn('[magic] could not hash refresh', e.message);
  }
}

// --- API: demo endpoints -----------------------------------------------------
app.get('/api/config', (_req, res) => {
  res.status(200).json({ app: 'own-chat', magicLink: true, banner: null, env: NODE_ENV });
});
app.get('/api/banner', (_req, res) => res.status(200).send(''));
app.get('/api/user', (req, res) => {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : (req.cookies?.jwt || '');
  if (!token) return res.status(200).json({ user: null });
  try {
    const payload = jwt.verify(token, ACCESS_TOKEN_SECRET);
    res.status(200).json({ id: payload.sub || 'unknown', email: payload.email || 'unknown@no-mail.invalid', role: payload.role || 'user' });
  } catch {
    res.status(200).json({ user: null });
  }
});
app.post('/api/auth/refresh', (req, res) => {
  const rt = req.cookies?.refreshToken;
  if (!rt) return res.status(401).json({ error: 'No refresh token' });
  let payload;
  try {
    payload = jwt.verify(rt, REFRESH_TOKEN_SECRET);
  } catch {
    return res.status(401).json({ error: 'Invalid refresh token' });
  }
  const access = signAccess({ sub: payload.sub, email: 'demo1@no-mail.invalid', role: 'user' });
  const refresh = signRefresh({ sub: payload.sub });
  setAuthCookies(res, access, refresh);
  res.status(200).json({ ok: true });
});
app.post('/api/auth/logout', (_req, res) => {
  clearAuthCookies(res);
  res.status(200).json({ ok: true });
});

// --- Magic link flow ---------------------------------------------------------
// IMPORTANT: define /m/signed BEFORE /m/:token so it doesn't get captured.

// 2) Confirmation page (served directly)
app.get('/m/signed', (_req, res) => {
  const target = FRONTEND_ORIGIN;
  log.info('[magic] served /m/signed page');
  res
    .type('html')
    .send(`<!doctype html>
<meta charset="utf-8">
<title>Signed in</title>
<style>
  html,body { height:100%; }
  body { display:flex; align-items:flex-start; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto; margin: 2rem; }
  h1 { font-size: 42px; margin: 0; }
</style>
<h1>Signed in ✔</h1>
<script>
(function () {
  try {
    var tgt = new URL('${target}', location.href).origin;
    if (window.opener) window.opener.postMessage({ type: 'magic:signed' }, tgt);
  } catch (e) {}
  setTimeout(function () { location.replace('${target}'); }, 100);
})();
</script>`);
});

// 1) Magic link (strict JWT pattern to avoid matching "signed")
app.get('/m/:token([A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+)', (req, res) => {
  const token = req.params.token;
  log.info('[magic] GET /m/:token hit param token');
  try {
    const payload = jwt.verify(token, MAGIC_LINK_SECRET);
    log.info('[magic] token verified', { aud: payload.aud || 'magic-link', sub: payload.sub, iat: payload.iat, exp: payload.exp });

    // Fake user lookup
    const user = { id: payload.sub, email: 'demo1@no-mail.invalid', role: 'user' };
    log.info('[magic] user found', { id: user.id, email: user.email, role: user.role });

    const access = signAccess({ sub: user.id, email: user.email, role: user.role });
    const refresh = signRefresh({ sub: user.id });
    log.info('[magic] signed tokens { access: ****, refresh: **** }');

    rememberRefresh(refresh);
    setAuthCookies(res, access, refresh);
    log.info('[magic] set cookies', { cookieNames: ['jwt','token','accessToken','refreshToken'], sameSite: 'None', secure: true });

    return res.redirect(302, '/m/signed');
  } catch (e) {
    log.warn('[magic] invalid token: ' + (e?.message || 'unknown'));
    return res.status(401).send('invalid_token');
  }
});

// --- Static assets & safe fallbacks -----------------------------------------
const ROOT = path.resolve(__dirname, '..', '..');
const PUBLIC_DIR = path.join(ROOT, 'public');

if (fs.existsSync(path.join(PUBLIC_DIR, 'assets'))) {
  app.use('/assets', express.static(path.join(PUBLIC_DIR, 'assets'), { maxAge: '1h', fallthrough: true }));
}
app.get('/sw.js', (_req, res) => {
  res.type('application/javascript').send(`self.addEventListener('install',e=>self.skipWaiting());self.addEventListener('activate',e=>self.clients.claim());`);
});
app.get('/workbox-4c320e2c.js', (_req, res) => res.type('application/javascript').send(`/* workbox stub */`));

app.get([
  '/favicon.ico',
  '/assets/favicon-32x32.png',
  '/assets/favicon-16x16.png',
  '/assets/apple-touch-icon-180x180.png',
  '/assets/icon-192x192.png',
  '/assets/maskable-icon.png',
  '/assets/logo.svg',
  '/assets/silence.mp3',
  '/assets/fonts/Inter-Bold.woff2',
  '/assets/fonts/Inter-Regular.woff2',
  '/assets/fonts/Inter-SemiBold.woff2',
], (req, res, next) => {
  const safePath = path.normalize(req.path).replace(/^\/+/, '');
  const candidate = path.join(PUBLIC_DIR, safePath);
  if (candidate.startsWith(PUBLIC_DIR) && fs.existsSync(candidate)) {
    return res.sendFile(candidate);
  }
  if (req.path.endsWith('.svg')) return res.type('image/svg+xml').status(200).send('<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64"/>');
  if (req.path.endsWith('.mp3')) return res.type('audio/mpeg').status(200).send(Buffer.alloc(2));
  if (req.path.endsWith('.png')) return res.type('image/png').status(200).send(Buffer.alloc(1));
  if (req.path.endsWith('.ico')) return res.type('image/x-icon').status(200).send(Buffer.alloc(1));
  next();
});

// Simple placeholder pages for common routes
app.get(['/', '/login', '/c/new'], (_req, res) => {
  res.type('html').send(`<!doctype html>
<meta charset="utf-8">
<title>Own Chat</title>
<link rel="icon" href="/favicon.ico">
<style>body{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto;margin:2rem}pre{background:#f5f5f5;padding:1rem;border-radius:8px}</style>
<h1>Own Chat</h1>
<p>This is a minimal placeholder UI served by <code>api/server/index.js</code>.</p>
<p><a href="/m/signed">Test: signed page</a></p>
<pre id="out">loading...</pre>
<script>
fetch('/api/user', { credentials: 'include' }).then(r => r.json()).then(u => {
  document.getElementById('out').textContent = JSON.stringify(u, null, 2);
}).catch(e => { document.getElementById('out').textContent = String(e); });
</script>`);
});

// Catch-all
app.get('*', (_req, res) => res.status(200).type('text/plain').send('OK'));

// Error handler
app.use((err, _req, res, _next) => {
  log.error('Unhandled error:', err && err.stack ? err.stack : err);
  res.status(500).json({ error: 'server_error' });
});

// Boot
app.listen(PORT, () => log.info(`server listening on :${PORT}`));

