// api/routes/magic.js
const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const router = express.Router();

const ACCESS_SECRET  = process.env.JWT_SECRET;
const REFRESH_SECRET =
  process.env.REFRESH_TOKEN_SECRET ||
  process.env.JWT_REFRESH_SECRET ||
  process.env.JWT_SECRET;

const ACCESS_TTL  = process.env.JWT_EXPIRES_IN || '1h';
const REFRESH_TTL = process.env.REFRESH_TOKEN_EXPIRES_IN || '30d';
const MAGIC_SECRET = process.env.MAGIC_LINK_SECRET || ACCESS_SECRET;

// unified cookie options (must survive cross-site redirect)
const ONE_HOUR_MS   = 60 * 60 * 1000;
const THIRTY_D_MS   = 30 * 24 * 60 * 60 * 1000;
const BASE_COOKIE = {
  httpOnly: true,
  secure: true,          // Heroku uses HTTPS
  sameSite: 'none',      // <- IMPORTANT for redirect flow
  path: '/',
};

function signAccess(user) {
  const sub = String(user._id);
  return jwt.sign(
    {
      sub,
      id: sub,
      _id: sub,
      email: user.email,
      name: user.name,
      role: user.role || 'user',
      roles: Array.isArray(user.roles) ? user.roles : [user.role || 'user'],
      provider: 'magic',
    },
    ACCESS_SECRET,
    { expiresIn: ACCESS_TTL }
  );
}

function signRefresh(user) {
  const sub = String(user._id);
  return jwt.sign({ sub }, REFRESH_SECRET, { expiresIn: REFRESH_TTL });
}

// keep these near the top of magic.js if not already defined
const ONE_HOUR_MS  = 60 * 60 * 1000;
const THIRTY_D_MS  = 30 * 24 * 60 * 60 * 1000;
const BASE_COOKIE  = { sameSite: 'none', secure: true, path: '/' };

// REPLACE your current setAuthCookies with this version
function setAuthCookies(res, access, refresh) {
  // HttpOnly cookies for server-side auth
  res.cookie('jwt',          access,  { ...BASE_COOKIE, httpOnly: true,  maxAge: ONE_HOUR_MS });
  res.cookie('refreshToken', refresh, { ...BASE_COOKIE, httpOnly: true,  maxAge: THIRTY_D_MS });

  // Readable, one-shot cookie to seed localStorage.token in the client
  res.cookie('appToken',     access,  { ...BASE_COOKIE, httpOnly: false, maxAge: ONE_HOUR_MS });

  // Remove legacy/confusing names the client might check
  res.clearCookie('token',       { ...BASE_COOKIE });
  res.clearCookie('accessToken', { ...BASE_COOKIE });
}

/** Magic link consumer: /m/:token  (aud: "magic-link") */
router.get('/m/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const payload = jwt.verify(token, MAGIC_SECRET, { audience: 'magic-link' });
    const userId = payload.sub;

    const User = mongoose.model('User');
    const user = await User.findById(userId);
    if (!user) return res.status(404).send('User not found');

    // issue tokens
    const access  = signAccess(user);
    const refresh = signRefresh(user);

    // persist refresh token so the built-in /api/auth/refresh logic (and our shim) consider it valid
    if (!Array.isArray(user.refreshToken)) user.refreshToken = [];
    if (!user.refreshToken.includes(refresh)) {
      user.refreshToken.push(refresh);
      await user.save();
    }

    setAuthCookies(res, access, refresh);

    // small HTML bootstrap page that verifies and then lands in the app
    const target = (req.query.to && String(req.query.to)) || '/c/new';
    res.type('html').send(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Signing you in…</title></head>
<body style="font-family: system-ui, sans-serif; display:grid; place-items:center; height:100dvh;">
  <div>Signing you in…</div>
  <script>
    (async () => {
      try {
        const r = await fetch('/api/auth/session', { credentials: 'include' });
        if (r.ok) {
          location.replace('${target}?cb=' + Date.now());
        } else {
          location.replace('/login?from=magic&err=session');
        }
      } catch {
        location.replace('/login?from=magic&err=network');
      }
    })();
  </script>
</body></html>`);
  } catch (e) {
    return res.status(401).send('Invalid or expired link');
  }
});

/** Minimal session probe used by the client on boot */
router.get('/api/auth/session', (req, res) => {
  try {
    const raw =
      req.cookies?.jwt ||
      req.cookies?.token ||
      req.cookies?.accessToken ||
      (req.headers.authorization || '').replace(/^Bearer\s+/i, '');

    if (!raw) return res.status(401).end();
    const decoded = jwt.verify(raw, ACCESS_SECRET);
    return res.json({
      ok: true,
      user: {
        id: decoded.sub,
        email: decoded.email,
        name: decoded.name,
        roles: decoded.roles || [decoded.role || 'user'],
        provider: 'magic',
      },
    });
  } catch {
    return res.status(401).end();
  }
});

/** Refresh shim: re-issue access token from refresh cookie (method-agnostic) */
router.all('/api/auth/refresh', async (req, res) => {
  try {
    const rt = req.cookies?.refreshToken;
    if (!rt) return res.status(401).end();

    const { sub } = jwt.verify(rt, REFRESH_SECRET);
    const User = mongoose.model('User');
    const user = await User.findById(sub);
    if (!user) return res.status(401).end();

    // optionally enforce DB presence of refresh token
    if (!Array.isArray(user.refreshToken) || !user.refreshToken.includes(rt)) {
      // if you want to be strict, reject here:
      // return res.status(401).end();
      // for smoother UX, accept once and persist:
      user.refreshToken = Array.isArray(user.refreshToken) ? user.refreshToken : [];
      user.refreshToken.push(rt);
      await user.save();
    }

    const access = signAccess(user);
    setAuthCookies(res, access, rt);
    return res.json({ ok: true });
  } catch {
    return res.status(401).end();
  }
});

module.exports = router;
