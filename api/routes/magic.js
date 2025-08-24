// api/routes/magic.js
const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const router = express.Router();

const MAGIC_SECRET =
  process.env.MAGIC_LINK_SECRET ||
  process.env.JWT_SECRET;

// Use the exact same precedence the API uses to VERIFY refresh tokens
const REFRESH_SECRET =
  process.env.JWT_REFRESH_SECRET ||
  process.env.REFRESH_TOKEN_SECRET ||
  process.env.JWT_SECRET;

// ----- cookie helpers -----
const ONE_HOUR_MS  = 60 * 60 * 1000;
const THIRTY_D_MS  = 30 * 24 * 60 * 60 * 1000;

// Heroku/Chrome: SameSite=None requires Secure
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

  // extra names for wider compat with some builds
  res.cookie('token', access,         { ...BASE_COOKIE, maxAge: ONE_HOUR_MS });
  res.cookie('accessToken', access,   { ...BASE_COOKIE, maxAge: ONE_HOUR_MS });
}

// -----------------------------------------------------------------------------
// 1) Handshake page: writes localStorage and verifies session
// -----------------------------------------------------------------------------
router.get('/m/signed', (req, res) => {
  const jwtCookie = req.cookies?.jwt || '';
  let uid = '';

  try {
    const d = jwt.decode(jwtCookie) || {};
    uid = d.sub || d.id || d._id || '';
  } catch (_) {}

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

// -----------------------------------------------------------------------------
// 2) Magic link consumer: verify, set cookies, bounce to /m/signed
// -----------------------------------------------------------------------------
router.get('/m/:token', async (req, res) => {
  try {
    const { token } = req.params;

    const payload = jwt.verify(token, MAGIC_SECRET, { audience: 'magic-link' });
    const userId = payload.sub;

    const User = mongoose.model('User');
    const user = await User.findById(userId);
    if (!user) return res.status(404).send('User not found');

    // access token
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
      { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
    );

    // refresh token (signed with the same secret the server will VERIFY)
    const refresh = jwt.sign(
      { sub: userId },
      REFRESH_SECRET,
      { expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || '30d' }
    );

    setAuthCookies(res, access, refresh);
    return res.redirect('/m/signed');
  } catch (e) {
    return res.status(401).send('Invalid or expired link');
  }
});

module.exports = router;
