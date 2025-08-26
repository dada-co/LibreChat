const express = require('express');
const { AssistantBinding } = require('~/mongo/models/AssistantBinding');

const router = express.Router();
const ADMIN_KEY = process.env.ADMIN_API_KEY;

/**
 * Bind a Libre user to an OpenAI assistant.
 *
 * @route POST /assistants/bind
 * @example curl -X POST https://librechat.example.com/api/assistants/bind \
 *  -H "x-admin-key: <ADMIN_API_KEY>" \
 *  -H "Content-Type: application/json" \
 *  -d '{"libre_user_id":"6653f1a0e2...","assistant_id":"asst_abc123xyz"}'
 */
router.post('/', async (req, res) => {
  if (!ADMIN_KEY || req.headers['x-admin-key'] !== ADMIN_KEY) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const { libre_user_id, assistant_id } = req.body || {};

  if (!libre_user_id || typeof libre_user_id !== 'string') {
    return res.status(400).json({ error: 'missing_libre_user_id' });
  }

  if (!assistant_id || !assistant_id.startsWith('asst_')) {
    return res.status(400).json({ error: 'invalid_assistant_id' });
  }

  await AssistantBinding.updateOne(
    { user: libre_user_id },
    { $set: { assistant_id }, $setOnInsert: { createdAt: new Date() } },
    { upsert: true },
  );

  res.json({ ok: true });
});

module.exports = router;
