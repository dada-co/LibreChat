// api/routes/magic.js
const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const router = express.Router();

const MAGIC_SECRET = process.env.MAGIC_LINK_SECRET || process.env.JWT_SECRET;
const ACCESS_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';
const REFRESH_SECRET =
  process.env.REFRESH_TOKEN_SECRET || process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET;
const REFRESH_EXPIRES_IN = process.env.REFRESH_TOKEN_EXPIRES_IN || '30d';

const ONE_HOUR_MS  = 60 * 60 * 1000;
const THIRTY_D_MS  = 30 * 24 * 60 * 60 * 1000;

function setAuthCookies(res, accessToken, refreshToken) {
  const base = {
    httpOnly: true,
    sameSite: 'none', // survive redirects (required with Secure)
    secure: true,     // Heroku is HTTPS
    path: '/',
  };

  res.cookie('jwt', accessToken,        { ...base, maxAge: ONE_HOUR_MS });
  res.cookie('token', accessToken,      { ...base, maxAge: ONE_HOUR_MS });
  res.cookie('accessToken', accessToken,{ ...base, maxAge: ONE_HOUR_MS });
  res.cookie('refreshToken', refreshToken, { ...base, maxAge: THIRTY_D_MS });
}

/**
 * GET /m/:token
 * Verifies the magic token, issues access/refresh cookies, then redirects to a
 * server-rendered handshake page that seeds localStorage and checks /api/user.
 */
router.get('/m/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const payload = jwt.verify(token, MAGIC_SECRET, { audience: 'magic-link' });
    const userId = payload.sub;

    const User = mongoose.model('User');
    const user = await User.findById(userId);
    if (!user) return res.status(404).send('User not found');

    // Build the access token with the fields your UI may expect
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
      { expiresIn: ACCESS_EXPIRES_IN },
    );

    const refresh = jwt.sign({ sub: userId }, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRES_IN });

    setAuthCookies(res, access, refresh);

    // redirect to handshake page which will seed localStorage and verify /api/user
    return res.redirect('/m/signed');
  } catch (e) {
    return res.status(401).send('Invalid or expired link');
  }
});

/**
 * GET /m/signed
 * This page runs in the browser. It:
 * 1) Seeds localStorage.token with the server-seen jwt cookie value
 * 2) Calls /api/user (credentials: 'include') to ensure the session is good
 * 3) Sends you into the app (/) or to /login on failure
 */
router.get('/m/signed', (req, res) => {
  // Read back the jwt cookie server-side and safely embed for localStorage
  const jwtCookie = req.cookies?.jwt || '';
  const userId = (() => {
    try {
      const decoded = jwt.decode(jwtCookie) || {};
      return decoded.sub || decoded.id || decoded._id || '';
    } catch {
      return '';
    }
  })();

  const seedJWT = JSON.stringify(jwtCookie); // safe escaping for inline script
  const seedUID = JSON.stringify(userId);

  res.type('html').send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Signing you in…</title>
  <meta name="robots" content="noindex" />
  <style>
    body{font-family:system-ui, -apple-system, Segoe UI, Roboto, Inter, Arial, sans-serif;
         display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#0d0d0d;color:#fff}
    .box{max-width:520px;text-align:center}
    .sub{opacity:.7;font-size:14px;margin-top:8px}
    code{background:#1a1a1a;padding:2px 6px;border-radius:4px}
  </style>
</head>
<body>
  <div class="box">
    <div>🔑 Signing you in…</div>
    <div class="sub">If this hangs, refresh the page.</div>
  </div>
  <script>
    (async () => {
      try {
        // Seed localStorage for UIs that expect a token in web storage
        localStorage.setItem('token', ${seedJWT});
        if (${seedUID}) localStorage.setItem('userId', ${seedUID});

        // Verify the session with the API
        const r = await fetch('/api/user', { credentials: 'include' });
        if (!r.ok) throw new Error('unauthorized');

        // Nudge some UIs that key off a flag
        try { localStorage.setItem('loggedIn', '1'); } catch {}

        // Enter the app
        location.replace('/?from=magic&cb=' + Date.now());
      } catch (err) {
        location.replace('/login?from=magic&err=' + encodeURIComponent(String(err && err.message || 'unknown')));
      }
    })();
  </script>
</body>
</html>`);
});

module.exports = router;
