// api/routes/magic.js
const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const router = express.Router();

const MAGIC_SECRET = process.env.MAGIC_LINK_SECRET || process.env.JWT_SECRET;

// Reuse your existing User model registered by the app
// e.g., const User = mongoose.model('User'); (we'll query inside handler)

// Set cookies similar to normal login
function setAuthCookies(res, accessToken, refreshToken) {
  const base = {
    httpOnly: true,
    sameSite: 'lax',
    secure: true, // Heroku uses HTTPS
    path: '/',
  };
  // cover common cookie names used by different builds
  res.cookie('token', accessToken, base);
  res.cookie('jwt', accessToken, base);
  res.cookie('accessToken', accessToken, base);
  if (refreshToken) res.cookie('refreshToken', refreshToken, base);
}

// PUBLIC: consume the magic link → set cookies → redirect to app
// GET /m/:token
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
      { sub: userId, id: userId, _id: userId, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '1h' },
    );

    // refresh token (fallback to other names if needed)
    const refreshSecret =
      process.env.REFRESH_TOKEN_SECRET ||
      process.env.JWT_REFRESH_SECRET ||
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
