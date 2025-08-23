// api/routes/magic.js
const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const router = express.Router();
const MAGIC_SECRET = process.env.MAGIC_LINK_SECRET || process.env.JWT_SECRET;

// ✅ your cookie setter (kept as-is)
function setAuthCookies(res, accessToken, refreshToken) {
  const oneHour    = 60 * 60 * 1000;
  const thirtyDays = 30 * 24 * 60 * 60 * 1000;

  const base = {
    httpOnly: true,
    sameSite: 'none',   // survive cross-site redirects
    secure: true,       // required with SameSite=None on HTTPS
    path: '/',
  };

  res.cookie('jwt', accessToken,         { ...base, maxAge: oneHour });
  res.cookie('refreshToken', refreshToken,{ ...base, maxAge: thirtyDays });

  // compatibility names
  res.cookie('token', accessToken,       { ...base, maxAge: oneHour });
  res.cookie('accessToken', accessToken, { ...base, maxAge: oneHour });
}

// GET /m/:token → validate, set cookies, show handshake page
router.get('/m/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const payload = jwt.verify(token, MAGIC_SECRET, { audience: 'magic-link' });
    const userId = String(payload.sub);

    const User = mongoose.model('User');
    const user = await User.findById(userId).lean();
    if (!user) return res.status(404).send('User not found');

    const accessPayload = {
      sub: userId, id: userId, _id: userId,
      email: user.email, name: user.name,
      role: user.role ?? 'user',
      roles: user.roles ?? (user.role ? [user.role] : ['user']),
      provider: 'magic',
    };

    const access = jwt.sign(
      accessPayload,
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '1h' },
    );

    const refreshSecret =
      process.env.JWT_REFRESH_SECRET ||
      process.env.REFRESH_TOKEN_SECRET ||
      process.env.JWT_SECRET;

    const refresh = jwt.sign(
      { sub: userId },
      refreshSecret,
      { expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || '30d' },
    );

    setAuthCookies(res, access, refresh);

    // Handshake page: verify session, then go to the app (prevents login-bounce)
    const target = '/c/new';
    res.status(200).set({
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
      Pragma: 'no-cache',
      Expires: '0',
      'Content-Type': 'text/html; charset=utf-8',
    }).send(`<!doctype html>
<meta http-equiv="cache-control" content="no-store">
<title>Signing you in…</title>
<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;padding:24px}</style>
<p>Signing you in…</p>
<script>
(async () => {
  try {
    const r = await fetch('/api/user', { credentials: 'include' });
    if (r.ok) location.replace('${target}?cb=' + Date.now());
    else      location.replace('/login?from=magic&err=unauthorized');
  } catch {
    location.replace('/login?from=magic&err=network');
  }
})();
</script>`);
  } catch {
    return res.status(401).send('Invalid or expired link');
  }
});

module.exports = router;
