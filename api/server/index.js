// api/server/index.js
'use strict';

require('dotenv').config();

const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || undefined;

app.set('trust proxy', 1);
app.use(compression());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  cors({
    origin: FRONTEND_ORIGIN ? [FRONTEND_ORIGIN] : true,
    credentials: true,
  })
);

/* ------------------------------ tiny logger ---------------------------- */
const color = {
  green: (s) => `\x1b[32m${s}\x1b[39m`,
  yellow: (s) => `\x1b[33m${s}\x1b[39m`,
  red: (s) => `\x1b[31m${s}\x1b[39m`,
};
const logger = {
  info: (...a) => console.log(new Date().toISOString(), color.green('info'), ':', ...a),
  warn: (...a) => console.warn(new Date().toISOString(), color.yellow('warn'), ':', ...a),
  error: (...a) => console.error(new Date().toISOString(), color.red('error'), ':', ...a),
};

app.use((req, _res, next) => {
  const cookieKeys = Object.keys(req.cookies || {});
  logger.info(`[req] ${req.method} ${req.path} cookies: ${JSON.stringify(cookieKeys)}`);
  next();
});

/* --------------------- cookie -> Authorization bridge ------------------- */
const SKIP_BRIDGE = new Set(['/api/auth/refresh', '/api/auth/logout']);
app.use((req, _res, next) => {
  if (SKIP_BRIDGE.has(req.path)) {
    return next();
  }
  if (!req.headers.authorization) {
    const c = req.cookies || {};
    const t = c.jwt || c.token || c.accessToken;
    if (t) {
      req.headers.authorization = `Bearer ${t}`;
      logger.info('[bridge] Authorization set from cookie');
    }
  }
  next();
});

/* ------------------------ cookie helpers (secure) ----------------------- */
function setAccessCookies(res, accessToken) {
  const ONE_HOUR_MS = 60 * 60 * 1000;
  const opts = { httpOnly: true, sameSite: 'None', secure: true, path: '/', maxAge: ONE_HOUR_MS };
  res.cookie('jwt', accessToken, opts);
  res.cookie('token', accessToken, opts);
  res.cookie('accessToken', accessToken, opts);
}
function setRefreshCookie(res, refreshToken) {
  const THIRTY_D_MS = 30 * 24 * 60 * 60 * 1000;
  const opts = { httpOnly: true, sameSite: 'None', secure: true, path: '/', maxAge: THIRTY_D_MS };
  res.cookie('refreshToken', refreshToken, opts);
}

/* -------------------- /api/auth/refresh OVERRIDE (early) ---------------- */
app.post('/api/auth/refresh', async (req, res) => {
  logger.info('[refresh] override hit');
  try {
    const { refreshToken } = req.cookies || {};
    if (!refreshToken) return res.status(401).json({ error: 'missing_refresh_cookie' });

    const refreshSecret =
      process.env.REFRESH_TOKEN_SECRET ||
      process.env.JWT_REFRESH_SECRET ||
      process.env.JWT_SECRET;

    if (!refreshSecret || !process.env.JWT_SECRET) {
      logger.error('[refresh] secrets not configured');
      return res.status(500).json({ error: 'server_misconfigured' });
    }

    const payload = jwt.verify(refreshToken, refreshSecret);
    const userId = payload.sub || payload.id || payload._id;
    if (!userId) return res.status(401).json({ error: 'invalid_refresh' });

    const accessClaims = {
      sub: userId,
      id: userId,
      _id: userId,
      email: payload.email || '',
      role: payload.role || 'user',
      provider: 'magic',
    };
    const accessToken = jwt.sign(accessClaims, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || '1h',
    });

    setAccessCookies(res, accessToken);
    logger.info('[refresh] issued new access token');
    return res.status(200).json({ token: accessToken, ok: true });
  } catch (e) {
    logger.warn('[refresh] failed:', e?.message || String(e));
    return res.status(401).json({ error: 'invalid_refresh' });
  }
});

/* --------------------------- inline "magic" routes ---------------------- */
// Accepts a magic-link JWT, issues access+refresh cookies, and redirects to /m/signed
app.get('/m/:token', (req, res) => {
  const raw = req.params.token;
  logger.info('[magic] GET /m/:token hit param token');
  try {
    const magicSecret = process.env.MAGIC_LINK_SECRET || process.env.JWT_SECRET;
    if (!magicSecret) {
      logger.error('[magic] no MAGIC_LINK_SECRET/JWT_SECRET');
      return res.status(500).send('server_misconfigured');
    }
    const magic = jwt.verify(raw, magicSecret);
    logger.info('[magic] token verified', {
      aud: magic.aud,
      sub: magic.sub,
      iat: magic.iat,
      exp: magic.exp,
    });

    const userId = magic.sub || magic.id || magic._id || 'user';
    const accessClaims = {
      sub: userId,
      id: userId,
      _id: userId,
      email: magic.email || 'demo1@no-mail.invalid',
      role: 'user',
      provider: 'magic',
    };

    if (!process.env.JWT_SECRET) {
      logger.error('[magic] JWT_SECRET missing');
      return res.status(500).send('server_misconfigured');
    }

    const access = jwt.sign(accessClaims, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || '1h',
    });

    const refreshSecret =
      process.env.REFRESH_TOKEN_SECRET ||
      process.env.JWT_REFRESH_SECRET ||
      process.env.JWT_SECRET;

    const refresh = jwt.sign(
      { sub: userId, email: accessClaims.email, role: accessClaims.role },
      refreshSecret,
      { expiresIn: process.env.REFRESH_EXPIRES_IN || '30d' }
    );

    logger.info('[magic] signed tokens { access: ****, refresh: **** }');
    setRefreshCookie(res, refresh);
    setAccessCookies(res, access);
    logger.info('[magic] set cookies { cookieNames: ["jwt","token","accessToken","refreshToken"], sameSite: "None", secure: true }');

    return res.redirect(302, '/m/signed');
  } catch (e) {
    logger.warn('[magic] invalid token:', e?.message || String(e));
    return res.status(401).send('invalid_token');
  }
});

app.get('/m/signed', (_req, res) => {
  res
    .status(200)
    .send('<!doctype html><meta charset="utf-8"><title>Signed</title><h1>Signed in ✔</h1>');
});

/* -------------------------- minimal API fallbacks ----------------------- */
app.get('/api/user', (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'missing_token' });

    const data = jwt.verify(token, process.env.JWT_SECRET);
    const user = {
      id: data.sub || data.id || data._id,
      email: data.email || 'demo1@no-mail.invalid',
      role: data.role || 'user',
    };
    return res.status(200).json({ user });
  } catch (e) {
    return res.status(401).json({ error: 'invalid_token' });
  }
});

// Your frontend seems to call these; respond benignly
app.get('/api/config', (_req, res) => {
  res.status(200).json({
    ok: true,
    auth: { sameSite: 'None', secure: true, provider: 'magic-link' },
    env: NODE_ENV,
  });
});
app.get('/api/banner', (_req, res) => res.status(200).send(''));

/* ------------------------------ static files ---------------------------- */
const STATIC_DIR = process.env.STATIC_DIR || path.resolve(process.cwd(), 'public');
app.use(express.static(STATIC_DIR, { index: false, maxAge: NODE_ENV === 'production' ? '1y' : 0 }));

app.get('/sw.js', (req, res) => {
  const swPath = path.join(STATIC_DIR, 'sw.js');
  res.sendFile(swPath, (err) => {
    if (err) {
      logger.warn('sw.js not found at', swPath);
      res.status(404).end();
    }
  });
});

// SPA fallback
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  const indexPath = path.join(STATIC_DIR, 'index.html');
  res.sendFile(indexPath, (err) => {
    if (err) next(err);
  });
});

/* ----------------------------- error handler ---------------------------- */
app.use((err, _req, res, _next) => {
  logger.error('Unhandled error:', err?.message || err);
  res.status(500).json({ error: 'internal_error' });
});

/* ------------------------------- start up ------------------------------- */
const server = app.listen(PORT, () => {
  logger.info(`Server listening on :${PORT}`);
});

process.on('uncaughtException', (err) => logger.error('uncaughtException:', err?.message || err));
process.on('unhandledRejection', (r) => logger.error('unhandledRejection:', r?.message || String(r)));

module.exports = { app, server };
