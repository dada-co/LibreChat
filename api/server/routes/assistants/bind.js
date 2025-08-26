const express = require('express');
const { AssistantBinding } = require('~/mongo/models/AssistantBinding');
const { logger } = require('~/config');

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
  logger.debug('[/assistants/bind] Request body:', req.body);
  try {
    if (!ADMIN_KEY || req.headers['x-admin-key'] !== ADMIN_KEY) {
      logger.warn('[/assistants/bind] Unauthorized request');
      return res.status(401).json({ error: 'unauthorized' });
    }

    const { libre_user_id, assistant_id } = req.body || {};

    if (!libre_user_id || typeof libre_user_id !== 'string') {
      logger.warn('[/assistants/bind] Missing or invalid libre_user_id', { libre_user_id });
      return res.status(400).json({ error: 'missing_libre_user_id' });
    }

    if (!assistant_id || !assistant_id.startsWith('asst_')) {
      logger.warn('[/assistants/bind] Invalid assistant_id', { assistant_id });
      return res.status(400).json({ error: 'invalid_assistant_id' });
    }

    await AssistantBinding.updateOne(
      { user: libre_user_id },
      { $set: { assistant_id }, $setOnInsert: { createdAt: new Date() } },
      { upsert: true },
    );

    logger.info('[/assistants/bind] Bound user to assistant', { libre_user_id, assistant_id });
    res.json({ ok: true });
  } catch (error) {
    logger.error('[/assistants/bind] Error binding assistant', error);
    res.status(500).json({ error: 'internal_server_error' });
  }
});

module.exports = router;
