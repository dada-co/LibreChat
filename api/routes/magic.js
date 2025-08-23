// api/routes/magic.js
const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const router = express.Router();

const MAGIC_SECRET = process.env.MAGIC_LINK_SECRET || process.env.JWT_SECRET;
const JWT_SECRET = process.env.JWT_SECRET;

// --- cookie helper: robust attributes for cross-site redirect reliability ---
function setAuthCookies(res, accessToken, refreshToken) {
  const oneHour    = 60 * 60 * 1000;             // 1h
  const thirtyDays = 30 * 24 * 60 * 60 * 1000;   // 30d

  // Host-only cookies (no "domain"), survive cross-site via SameSite=None
  const base = {
    httpOnly: true,
    secure: true,      // required with SameSite=None (Heroku is HTTPS)
    sameSite: 'none',
    path: '/',
  };

  // Canonical cookie names
  res.cookie('jwt', accessToken,            { ...base, maxAge: oneHour });
  res.cookie('refreshToken', refreshToken,  { ...base, maxAge: thirtyDays });

  // Compatibility cookie names some builds expect
  res.cookie('token', accessToken,          { ...base, maxAge: oneHour });
  res.cookie('accessToken', accessToken,    { ...base, maxAge: oneHour });
}

// --- GET /m/:token : consume magic link, set cookies, serve handshake page ---
router.get('/m/:token', async (req, res) => {
  try {
    if (!MAGIC_SECRET || !JWT_SECRET) {
      return res.status(500).send('Server auth not configured');
    }

    const { token } = req.params;
    // Verify the short-lived magic token we generated out-of-band
    const payload = jwt.verify(token, MAGIC_SECRET, { audience: 'magic-link' });
    const userId = String(payload.sub);

    // Use the already-registered User model
    const User = mongoose.model('User');
    const user = await User.findById(userId).lean();
    if (!user) return res.status(404).send('User not found');

    // Build access payload with common claims most JWT strategies expect
    const accessPayload = {
      sub: userId,
      id: userId,
      _id: userId,
      email: user.email,
      name: user.name,
      role: user.role ?? 'user',
      roles: user.roles ?? (user.role ? [user.role] : ['user']),
      provider: 'magic',
    };

    const access = jwt.sign(
      accessPayload,
      JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '1h' },
    );

    const refreshSecret =
      process.env.JWT_REFRESH_SECRET ||
      process.env.REFRESH_TOKEN_SECRET ||
      JWT_SECRET;

    const refresh = jwt.sign(
      { sub: userId },
      refreshSecret,
      { expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || '30d' },
    );

    setAuthCookies(res, access, refresh);

    // Handshake page: prove session via /api/user (with refresh fallback) then navigate
    const target = '/c/new'; // change if you want a different landing route
    res
      .status(200)
      .set({
        'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0',
        'Content-Type': 'text/html; charset=utf-8',
      })
      .send(`<!doctype html>
<meta http-equiv="cache-control" content="no-store">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Signing you in…</title>
<style>
  :root { color-scheme: light dark }
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;padding:24px}
  .muted{opacity:.7}
  code{background:rgba(0,0,0,.05);padding:.2em .4em;border-radius:4px}
</style>
<h1>Signing you in…</h1>
<p class="muted">One moment while we verify your session.</p>
<pre id="log" class="muted" style="white-space:pre-wrap"></pre>
<script>
(async () => {
  const target = ${JSON.stringify(target)};
  const log = (m) => { try { const el = document.getElementById('log'); el.textContent += m + "\\n"; } catch(_){} };

  async function getUser() {
    return fetch('/api/user?cb=' + Date.now(), {
      credentials: 'include',
      cache: 'no-store',
      headers: { 'cache-control': 'no-store', 'pragma': 'no-cache' },
    });
  }

  async function refresh() {
    return fetch('/api/auth/refresh?cb=' + Date.now(), {
      method: 'POST',
      credentials: 'include',
      cache: 'no-store',
      headers: { 'cache-control': 'no-store', 'pragma': 'no-cache' },
    });
  }

  try {
    let r = await getUser();
    log('GET /api/user → ' + r.status);
    if (r.ok) return location.replace(target + '?cb=' + Date.now());

    if (r.status === 401) {
      const rr = await refresh();
      log('POST /api/auth/refresh → ' + rr.status);
      if (rr.ok) {
        r = await getUser();
        log('GET /api/user (after refresh) → ' + r.status);
        if (r.ok) return location.replace(target + '?cb=' + Date.now());
      }
    }

    try { const txt = await r.text(); if (txt) log('Response body: ' + txt); } catch {}
    location.replace('/login?from=magic&err=session');
  } catch (e) {
    log('Network error: ' + (e && e.message ? e.message : e));
    location.replace('/login?from=magic&err=network');
  }
})();
</script>`);
  } catch (e) {
    return res.status(401).send('Invalid or expired link');
  }
});

module.exports = router;
