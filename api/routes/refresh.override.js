// api/routes/refresh.override.js
const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const router = express.Router();

const ONE_HOUR_MS   = 60 * 60 * 1000;
const THIRTY_D_MS   = 30 * 24 * 60 * 60 * 1000;
const BASE_COOKIE   = { httpOnly: true, sameSite: 'None', secure: true, path: '/' };
const ACCESS_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET =
  process.env.REFRESH_TOKEN_SECRET || process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET;

function setAuthCookies(res, access, refresh) {
  res.cookie('jwt',         access,  { ...BASE_COOKIE, maxAge: ONE_HOUR_MS });
  res.cookie('token',       access,  { ...BASE_COOKIE, maxAge: ONE_HOUR_MS });
  res.cookie('accessToken', access,  { ...BASE_COOKIE, maxAge: ONE_HOUR_MS });
  res.cookie('refreshToken',refresh, { ...BASE_COOKIE, maxAge: THIRTY_D_MS });
}

function clearAuthCookies(res) {
  for (const n of ['jwt', 'token', 'accessToken', 'refreshToken']) {
    res.clearCookie(n, BASE_COOKIE);
  }
}

/**
 * Override the default refresh to avoid 302 redirects.
 * Always respond with JSON (200/401) so the SPA stays on-page.
 */
router.post('/api/auth/refresh', async (req, res) => {
  try {
    const rt = req.cookies?.refreshToken;
    if (!rt) return res.status(401).json({ ok: false, error: 'no-refresh-cookie' });

    const payload = jwt.verify(rt, REFRESH_SECRET);
    const userId = payload.sub;

    const User = mongoose.model('User');
    const user = await User.findById(userId);
    if (!user) return res.status(401).json({ ok: false, error: 'user-missing' });

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
      ACCESS_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '1h' },
    );

    // rotate refresh too
    const refresh = jwt.sign({ sub: userId }, REFRESH_SECRET, {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || '30d',
    });

    setAuthCookies(res, access, refresh);
    return res.status(200).json({ ok: true });
  } catch (e) {
    clearAuthCookies(res);
    return res.status(401).json({ ok: false, error: 'invalid-refresh' });
  }
});

module.exports = router;
