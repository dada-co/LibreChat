const { getAssistantIdForUser, ensureThread, addUserMessage, streamRun } = require('~/server/services/assistants');
const { ThreadBinding } = require('~/mongo/models/ThreadBinding');

async function postMessageViaAssistant(req, res) {
  const libreUserId = String(req.user.id || req.user._id || '');
  const text = String(req.body.text || '');

  try {
    const assistantId = await getAssistantIdForUser(libreUserId);
    const threadId = await ensureThread(libreUserId, assistantId);

    await addUserMessage(threadId, text);

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.flushHeaders();

    let buffer = '';
    await streamRun(threadId, assistantId, (delta) => {
      buffer += delta;
      res.write(`data: ${JSON.stringify({ delta })}\n\n`);
    });

    await ThreadBinding.updateOne({ thread_id: threadId }, { $set: { last_message_at: new Date() } });

    res.write('event: done\ndata: {}\n\n');
    res.end();
  } catch (e) {
    const code = e && e.message === 'assistant_not_configured' ? 422 : 500;
    res.status(code).json({ error: e && e.message ? e.message : 'server_error' });
  }
}

module.exports = { postMessageViaAssistant };
