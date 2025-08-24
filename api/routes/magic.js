const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const router = express.Router();

const MAGIC_SECRET =
  process.env.MAGIC_LINK_SECRET ||
  process.env.JWT_SECRET;

const DEBUG_FLAG = String(process.env.MAGIC_DEBUG || '').toLowerCase() === 'true';
const dbg = (req) => DEBUG_FLAG || req.query.debug === '1';
const red = (s, head = 10, tail = 6) =>
  !s ? '∅' : (s.length <= head + tail ? s : `${s.slice(0, head)}…${s.slice(-tail)}`);

const log = (req, ...args) => { if (dbg(req)) console.log('[magic]', ...args); };
const warn = (req, ...args) => { if (dbg(req)) console.warn('[magic]', ...args); };
const err = (req, ...args) => { console.error('[magic]', ...args); };

/* Cookie helpers */
const ONE_HOUR_MS  = 60 * 60 * 1000;
const THIRTY_D_MS  = 30 * 24 * 60 * 60 * 1000;

// Cross-site redirect requires SameSite=None + Secure
const BASE_COOKIE = {
  httpOnly: true,
  sameSite: 'None',
  secure: true,
  path: '/',
};

function setAuthCookies(res, access, refresh) {
  // canonical names
  res.cookie('jwt', access,           { ...BASE_COOKIE, maxAge: ONE_HOUR_MS });
  res.cookie('refreshToken', refresh, { ...BASE_COOKIE, maxAge: THIRTY_D_MS });

  // “compatible” names some builds look for
  res.cookie('token', access,         { ...BASE_COOKIE, maxAge: ONE_HOUR_MS });
  res.cookie('accessToken', access,   { ...BASE_COOKIE, maxAge: ONE_HOUR_MS });
}

/* 1) Handshake page: verify session client-side then enter the app */
router.get('/m/signed', (req, res) => {
  const jwtCookie = req.cookies?.jwt || '';
  let uid = '';
  try {
    const d = jwt.decode(jwtCookie) || {};
    uid = d.sub || d.id || d._id || '';
  } catch {}

  log(req, 'GET /m/signed',
    'cookie keys:', Object.keys(req.cookies || []),
    'jwt:', red(jwtCookie));

  res.type('html').send(`<!doctype html>
<html><head><meta charset="utf-8"/><title>Signing you in…</title><meta name="robots" content="noindex"/></head>
<body style="font:16px/1.4 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:24px;">
  <div>Signing you in…</div>
  <script>
  (async () => {
    try {
      try {
        localStorage.setItem('token', ${JSON.stringify(jwtCookie)});
        ${uid ? `localStorage.setItem('userId', ${JSON.stringify(uid)});` : ''}
      } catch {}
      const r = await fetch('/api/user', { credentials: 'include' });
      if (!r.ok) throw new Error('unauthorized');
      try { localStorage.setItem('loggedIn', '1'); } catch {}
      location.replace('/?from=magic&cb=' + Date.now());
    } catch (e) {
      location.replace('/login?from=magic&err=' + encodeURIComponent(e.message || 'unknown'));
    }
  })();
  </script>
</body></html>`);
});

/* 2) Consume the magic link, set cookies, persist refresh token, redirect */
router.get('/m/:token', async (req, res) => {
  try {
    const { token } = req.params;
    log(req, 'GET /m/:token hit',
      'param token:', red(token));

    const payload = jwt.verify(token, MAGIC_SECRET, { audience: 'magic-link' });
    log(req, 'token verified',
      { aud: payload.aud, sub: payload.sub, iat: payload.iat, exp: payload.exp });

    const userId = payload.sub;
    const User = mongoose.model('User');
    const user = await User.findById(userId);
    if (!user) {
      warn(req, 'user not found for id:', userId);
      return res.status(404).send('User not found');
    }

    log(req, 'user found',
      { id: String(user._id), email: user.email, role: user.role });

    const access = jwt.sign(
      {
        sub: userId,
        id: userId,
        _id: userId,
        email: user.email,
        name: user.name || '',
        role: user.role || 'user',
        roles: [user.role || 'user'],
        provider: 'magic',
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '1h' },
    );

    const refreshSecret =
      process.env.REFRESH_TOKEN_SECRET ||
      process.env.JWT_REFRESH_SECRET ||
      process.env.JWT_SECRET;

    const refresh = jwt.sign(
      { sub: userId },
      refreshSecret,
      { expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || '30d' },
    );

    log(req, 'signed tokens',
      { access: red(access), refresh: red(refresh) });

    // ✅ Persist hashed refresh so /api/auth/refresh accepts it
    const hash = await bcrypt.hash(refresh, 10);
    const beforeLen = (user.refreshToken || []).length;
    user.refreshToken = (user.refreshToken || []).filter(Boolean).slice(-4);
    user.refreshToken.push(hash);
    await user.save();
    const afterLen = (user.refreshToken || []).length;

    log(req, 'saved refresh hash',
      { listLenBefore: beforeLen, listLenAfter: afterLen, hash: red(hash) });

    setAuthCookies(res, access, refresh);

    log(req, 'set cookies',
      {
        cookieNames: ['jwt','token','accessToken','refreshToken'],
        sameSite: BASE_COOKIE.sameSite,
        secure: BASE_COOKIE.secure,
      });

    log(req, 'redirect -> /m/signed');
    return res.redirect('/m/signed');
  } catch (e) {
    err(req, 'magic error', e && e.message);
    return res.status(401).send('Invalid or expired link');
  }
});

module.exports = router;
