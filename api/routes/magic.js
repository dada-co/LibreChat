// api/routes/magic.js
const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const router = express.Router();

const MAGIC_SECRET = process.env.MAGIC_LINK_SECRET || process.env.JWT_SECRET;

// cookie helper (SameSite=None + Secure for cross-site redirect reliability)
function setAuthCookies(res, accessToken, refreshToken) {
  const oneHour    = 60 * 60 * 1000;
  const thirtyDays = 30 * 24 * 60 * 60 * 1000;

  const base = {
    httpOnly: true,
    sameSite: 'none',     // <- important: survive cross-site redirects
    secure: true,         // <- required with SameSite=None (Heroku is HTTPS)
    path: '/',
  };

  // canonical names
  res.cookie('jwt', accessToken, { ...base, maxAge: oneHour });
  res.cookie('refreshToken', refreshToken, { ...base, maxAge: thirtyDays });

  // extra names for broader compatibility with some builds
  res.cookie('token', accessToken, { ...base, maxAge: oneHour });
  res.cookie('accessToken', accessToken, { ...base, maxAge: oneHour });
}

// PUBLIC: consume the magic link → set cookies → redirect to app
// GET /m/:token
router.get('/m/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const payload = jwt.verify(token, MAGIC_SECRET, { audience: 'magic-link' });
    const userId = String(payload.sub);

    // use already-registered model
    const User = mongoose.model('User');
    const user = await User.findById(userId).lean();
    if (!user) return res.status(404).send('User not found');

    // --- build an access payload most JWT strategies accept ---
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

    // land straight in the app
    return res.redirect('/');
  } catch (e) {
    return res.status(401).send('Invalid or expired link');
  }
});

module.exports = router;
