// api/routes/magic.js
const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const router = express.Router();

const MAGIC_SECRET = process.env.MAGIC_LINK_SECRET || process.env.JWT_SECRET;

// ----- cookie helpers -----
const ONE_HOUR_MS = 60 * 60 * 1000;
const THIRTY_D_MS = 30 * 24 * 60 * 60 * 1000;

// NOTE: Heroku/Chrome require SameSite=None with Secure for cross-site redirects
const BASE_COOKIE = {
  httpOnly: true,
  sameSite: 'None',
  secure: true,
  path: '/',
};

function setAuthCookies(res, access, refresh) {
  // canonical names
  res.cookie('jwt', access, { ...BASE_COOKIE, maxAge: ONE_HOUR_MS });
  res.cookie('refreshToken', refresh, { ...BASE_COOKIE, maxAge: THIRTY_D_MS });

  // extra names for wider compat with some middlewares
  res.cookie('token', access, { ...BASE_COOKIE, maxAge: ONE_HOUR_MS });
  res.cookie('accessToken', access, { ...BASE_COOKIE, maxAge: ONE_HOUR_MS });
}

function clearAuthCookies(res) {
  for (const n of ['jwt', 'token', 'accessToken', 'refreshToken']) {
    res.clearCookie(n, BASE_COOKIE);
  }
}

// -----------------------------------------------------------------------------
// 1) Handshake/finisher page (define BEFORE the token route)
//    Writes token to localStorage in formats the SPA expects.
// -----------------------------------------------------------------------------
router.get('/m/signed', (req, res) => {
  const jwtCookie = req.cookies?.jwt || '';
  let uid = '';
  try {
    const d = jwt.decode(jwtCookie) || {};
    uid = d.sub || d.id || d._id || '';
  } catch (_) {
    /* noop */
  }

  console.log('[magic] GET /m/signed', {
    jwtPresent: !!jwtCookie,
    cookieHeader: req.headers.cookie || null,
  });

  res.set('Cache-Control', 'no-store');

  // IMPORTANT: write the token as a *plain string*
  res.type('html').send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Signing you in…</title>
  <meta name="robots" content="noindex" />
</head>
<body style="font:16px/1.4 system-ui, -apple-system, Segoe UI, Roboto, sans-serif;padding:24px;">
  <div>Signing you in…</div>
  <script>
  (async () => {
    const token = ${JSON.stringify(jwtCookie || '')};
    const userId = ${JSON.stringify(uid || '')};

    console.log('[magic] handshake start', {
      tokenPresent: !!token,
      userId,
      cookieEnabled: navigator.cookieEnabled,
      cookies: document.cookie,
    });

    try {
      if (token) {
        localStorage.setItem('token', token);
        localStorage.setItem('accessToken', token);
        localStorage.setItem('jwt', token);
        localStorage.setItem('loggedIn', '1');
        if (userId) localStorage.setItem('userId', userId);
        try { localStorage.setItem('auth', JSON.stringify({ token, userId })); } catch {}
        console.log('[magic] stored token in localStorage');
      }
    } catch (err) {
      console.error('[magic] localStorage error', err);
    }

    try {
      // Bust cache and accept 200 or 304
      const r = await fetch('/api/user?fresh=' + Date.now(), { credentials: 'include', cache: 'no-store' });
      console.log('[magic] /api/user response', r.status, r.statusText);
      if (r.status !== 200 && r.status !== 304) throw new Error('unauthorized:' + r.status);
    } catch (e) {
      console.error('[magic] /api/user request failed', e);
      location.replace('/login?from=magic&err=' + encodeURIComponent(e.message || 'unknown'));
      return;
    }

    const params = new URLSearchParams(location.search);
    const next = params.get('next') || '/?from=magic&cb=' + Date.now();
    console.log('[magic] success, redirecting to', next);
    location.replace(next);
  })();
  </script>
</body>
</html>`);
});

// -----------------------------------------------------------------------------
// 2) Token consumer: verifies magic link, sets cookies, redirects to /m/signed
// -----------------------------------------------------------------------------
router.get('/m/:token', async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store');

    const { token } = req.params;
    console.log('[magic] GET /m/:token hit param token:', token.slice(0, 40) + '…');

    const payload = jwt.verify(token, MAGIC_SECRET, { audience: 'magic-link' });
    console.log('[magic] token verified', {
      aud: payload.aud,
      sub: payload.sub,
      iat: payload.iat,
      exp: payload.exp,
    });

    const userId = payload.sub;

    const User = mongoose.model('User');
    const user = await User.findById(userId);
    if (!user) return res.status(404).send('User not found');

    console.log('[magic] user found', { id: String(user._id), email: user.email, role: user.role });

    // sign access token with claims LibreChat expects
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
      process.env.REFRESH_TOKEN_SECRET || process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET;

    const refresh = jwt.sign({ sub: userId }, refreshSecret, {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || '30d',
    });

    console.log('[magic] signed tokens', {
      access: access.slice(0, 30) + '…' + access.slice(-6),
      refresh: refresh.slice(0, 30) + '…' + refresh.slice(-6),
    });

    // OPTIONAL: persist refresh hashes if your schema has it
    try {
      const bcrypt = require('bcryptjs');
      const hash = await bcrypt.hash(refresh, 10);
      const max = 5;
      const list = Array.isArray(user.refreshToken) ? user.refreshToken : [];
      const trimmed = list.concat(hash).slice(-max);
      if (trimmed.length !== list.length) {
        await User.updateOne({ _id: userId }, { $set: { refreshToken: trimmed } });
      }
      console.log('[magic] saved refresh hash', {
        listLenBefore: list.length,
        listLenAfter: trimmed.length,
        hash: hash.slice(0, 12) + '…',
      });
    } catch {
      /* noop */
    }

    setAuthCookies(res, access, refresh);
    console.log('[magic] set cookies', {
      cookieNames: ['jwt', 'token', 'accessToken', 'refreshToken'],
      sameSite: 'None',
      secure: true,
    });

    // finish on the handshake page (writes localStorage + verifies /api/user)
    return res.redirect('/m/signed');
  } catch (e) {
    console.error('[magic] error', e && (e.stack || e.message || e));
    clearAuthCookies(res);
    return res.status(401).send('Invalid or expired link');
  }
});

module.exports = router;
