// api/routes/admin.users.js
const express = require('express');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');

const router = express.Router();
const ADMIN_KEY = process.env.ADMIN_API_KEY;

// GET /api/admin/users
router.get('/users', async (req, res) => {
  try {
    if (!ADMIN_KEY || req.headers['x-admin-key'] !== ADMIN_KEY) {
      return res.status(401).json({ error: 'unauthorized' });
    }

    const {
      limit: limitRaw,
      offset: offsetRaw,
      search,
      email,
      username,
      provider,
      role,
    } = req.query || {};

    const limit = Math.min(Math.max(parseInt(limitRaw, 10) || 50, 1), 200);
    const offset = Math.max(parseInt(offsetRaw, 10) || 0, 0);

    const User = mongoose.model('User');

    const query = {};

    if (email) {
      query.email = String(email).toLowerCase();
    }

    if (username) {
      query.username = String(username).toLowerCase();
    }

    if (provider) {
      query.provider = provider;
    }

    if (role) {
      query.role = role;
    }

    if (search) {
      const regex = new RegExp(String(search).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      query.$or = [
        { email: regex },
        { username: regex },
        { name: regex },
      ];
    }

    const [users, total] = await Promise.all([
      User.find(query)
        .select(
          'email username name role provider emailVerified twoFactorEnabled idOnTheSource createdAt updatedAt',
        )
        .sort({ createdAt: -1 })
        .skip(offset)
        .limit(limit)
        .lean(),
      User.countDocuments(query),
    ]);

    return res.json({
      total,
      count: users.length,
      limit,
      offset,
      users,
    });
  } catch (err) {
    console.error('[admin.users] error', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// POST /api/admin/users
router.post('/users', async (req, res) => {
  try {
    if (!ADMIN_KEY || req.headers['x-admin-key'] !== ADMIN_KEY) {
      return res.status(401).json({ error: 'unauthorized' });
    }

    const { email, username, password, name, role = 'user' } = req.body || {};
    if (!email && !username) return res.status(400).json({ error: 'email or username required' });
    if (!password) return res.status(400).json({ error: 'password required' });

    const User = mongoose.model('User');

    // Ensure uniqueness
    const query = email ? { email: email.toLowerCase() } : { username: username.toLowerCase() };
    const exists = await User.findOne(query);
    if (exists) return res.status(409).json({ error: 'user exists' });

    // Hash password (if your model already hashes on save, you can skip this)
    const hash = await bcrypt.hash(String(password), 12);

    const doc = { name, password: hash };
    if (email) doc.email = email.toLowerCase();
    if (username) doc.username = username.toLowerCase();

    // Be flexible with schema: some have role, others roles[]
    if ('role' in User.schema.paths) doc.role = role;
    if ('roles' in User.schema.paths) doc.roles = [role];

    const user = await User.create(doc);
    return res.status(201).json({ id: user._id, email: user.email, username: user.username || null });
  } catch (err) {
    console.error('[admin.users] error', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

module.exports = router;
