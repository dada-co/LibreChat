// api/server/index.js
'use strict';

/**
 * Minimal, safe Express server with:
 *  - Cookie→Authorization bridge
 *  - /api/auth/refresh override (must be registered before other routers)
 *  - Static assets + SPA fallback
 *  - Clean logging and error handling for Node 22.x
 */

require('dotenv').config();

const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const cors = require('cors');
const jwt = require('jsonwebtoken');

// ⬇️ If your routes live elsewhere, update these paths accordingly.
const magicRoutes = require('./routes/magic'); // e.g., api/server/routes/magic.js
const routes = require('./routes');            // e.g., api/server/routes/index.js (exports { auth, api, ... })

const app = express();

/* --------------------------- basic app config --------------------------- */

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Allow frontend origin if set; otherwise, default to permissive in dev
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
  gray: (s) => `\x1b[90m${s}\x1b[39m`,
};
const logger = {
  info: (...a) => console.log(new Date().toISOString(), color.green('info'), ':', ...a),
  warn: (...a) => console.warn(new Date().toISOString(), color.yellow('warn'), ':', ...a),
  error: (...a) => console.error(new Date().toISOString(), color.red('error'), ':', ...a),
};

// Request log (method, path, cookies present)
app.use((req, _res, next) => {
  const cookieKeys = Object.keys(req.cookies || {});
  logger.info(`[req] ${req.method} ${req.path} cookies: ${JSON.stringify(cookieKeys)}`);
  next();
});

/* --------------------- cookie -> Authorization bridge ------------------- */

const SKIP_BRIDGE = new Set(['/api/auth/refresh', '/api/auth/logout']);
app.use((req, _res, next) => {
  if (SKIP_BRIDGE.has(req.path)) {
    logger.info(`[bridge] SKIP on ${req.path}`);
    return next();
  }
  if (!req.headers.authorization) {
    const c = req.cookies || {};
    const t = c.jwt || c.token || c.accessToken;
    if (t) {
      req.headers.authorization = `Bearer ${t}`;
      const left = t.slice(0, 7);
      const right = t.slice(-7);
      logger.info(`[bridge] Authorization set from cookie; jwt: ${left}...${right}`);
    }
  } else {
    logger.info('[bridge] Authorization already present');
  }
  next();
});

/* ------------------------- helper: cookie setter ------------------------ */

function setAccessCookies(res, accessToken) {
  const ONE_HOUR_MS = 60 * 60 * 1000;
  const BASE = {
    httpOnly: true,
    sameSite: 'None',
    secure: true,
    path: '/',
    maxAge: ONE_HOUR_MS,
  };
  res.cookie('jwt', accessToken, BASE);
  res.cookie('token', accessToken, BASE);
  res.cookie('accessToken', accessToken, BASE);
}

/* -------------------- /api/auth/refresh OVERRIDE (early) ---------------- */

/**
 * IMPORTANT:
 * This must be defined BEFORE any other auth/magic routers,
 * otherwise a previously-registered handler may redirect with 302.
 */
app.post('/api/auth/refresh', async (req, res) => {
  logger.info('[refresh] override hit');
  try {
    const { refreshToken } = req.cookies || {};
    if (!refreshToken) {
      logger.warn('[refresh] missing refresh cookie');
      return res.status(401).json({ error: 'missing_refresh_cookie' });
    }

    const refreshSecret =
      process.env.REFRESH_TOKEN_SECRET ||
      process.env.JWT_REFRESH_SECRET ||
      process.env.JWT_SECRET;

    if (!refreshSecret) {
      logger.error('[refresh] no refresh secret configured');
      return res.status(500).json({ error: 'server_misconfigured' });
    }

    // Verify refresh token
    const payload = jwt.verify(refreshToken, refreshSecret);
    const userId = payload.sub || payload.id || payload._id;
    if (!userId) {
      logger.warn('[refresh] refresh token missing subject');
      return res.status(401).json({ error: 'invalid_refresh' });
    }

    // Fetch user. If you use Mongoose, ensure the model is already registered elsewhere.
    // Require inline to avoid hard dependency in environments without mongoose.
    let user = null;
    try {
      const mongoose = require('mongoose');
      if (mongoose?.models?.User) {
        user = await mongoose.models.User.findById(userId).lean();
      }
    } catch {
      // ignore if mongoose isn't installed / used
    }

    // If no DB lookup is needed in your setup, you could skip the query. For safety:
    if (!user && process.env.REFRESH_ALLOW_MISSING_USER !== 'true') {
      logger.warn('[refresh] user not found for sub:', userId);
      return res.status(404).json({ error: 'user_not_found' });
    }

    const accessClaims = {
      sub: userId,
      id: userId,
      _id: userId,
      email: user?.email || '',
      name: user?.name || '',
      role: user?.role || 'user',
      roles: [user?.role || 'user'],
      provider: 'magic',
    };

    const accessToken = jwt.sign(
      accessClaims,
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
    );

    setAccessCookies(res, accessToken);
    logger.info('[refresh] issued new access token');
    return res.status(200).json({ token: accessToken, ok: true });
  } catch (e) {
    logger.warn('[refresh] failed:', e?.message || String(e));
    return res.status(401).json({ error: 'invalid_refresh' });
  }
});

/* ----------------------------- other routers ---------------------------- */

// Mount magic routes (e.g. /m/:token -> signs cookies and redirects)
app.use('/', magicRoutes);

// Mount the rest of your API routers (expects routes.auth, routes.api, etc.)
if (routes?.auth) app.use('/api/auth', routes.auth);
if (routes?.api) app.use('/api', routes.api);

/* ------------------------------ static files ---------------------------- */

/**
 * Serve your built frontend. Update STATIC_DIR if your build output is different.
 * Example common locations: ../../web/dist, ../../client/dist, ../../public
 */
const STATIC_DIR =
  process.env.STATIC_DIR ||
  path.resolve(process.cwd(), 'public');

app.use(express.static(STATIC_DIR, { index: false, maxAge: NODE_ENV === 'production' ? '1y' : 0 }));

// Service worker (often needs to be served at the root)
app.get('/sw.js', (req, res) => {
  const swPath = path.join(STATIC_DIR, 'sw.js');
  logger.info('[req] GET /sw.js');
  res.sendFile(swPath, (err) => {
    if (err) {
      logger.warn('sw.js not found at', swPath);
      res.status(404).end();
    }
  });
});

// SPA fallback: let the client-side router handle everything else
app.get('*', (req, res, next) => {
  // If request looks like API, skip to 404/next handlers
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

/* ------------------------------- process hooks -------------------------- */

process.on('uncaughtException', (err) => {
  logger.error('uncaughtException:', err?.message || err);
});

process.on('unhandledRejection', (reason) => {
  logger.error('unhandledRejection:', reason?.message || String(reason));
});

module.exports = { app, server };
