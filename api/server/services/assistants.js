const { AssistantBinding } = require('~/mongo/models/AssistantBinding');
const { ThreadBinding } = require('~/mongo/models/ThreadBinding');
const { openai } = require('./openai');

async function getAssistantIdForUser(libreUserId) {
  const row = await AssistantBinding.findOne({ user: libreUserId }).lean();
  if (!row || !row.assistant_id) {
    throw new Error('assistant_not_configured');
  }
  return row.assistant_id;
}

async function ensureThread(libreUserId, assistantId) {
  const existing = await ThreadBinding.findOne({ user: libreUserId, archived: false })
    .sort({ last_message_at: -1 })
    .lean();
  if (existing && existing.thread_id) {
    return existing.thread_id;
  }

  const created = await openai.beta.threads.create({
    metadata: { libre_user_id: libreUserId, assistant_id: assistantId },
  });

  await ThreadBinding.create({
    user: libreUserId,
    assistant_id: assistantId,
    thread_id: created.id,
    title: 'New chat',
    last_message_at: new Date(),
  });

  return created.id;
}

async function addUserMessage(threadId, text) {
  await openai.beta.threads.messages.create(threadId, { role: 'user', content: text });
}

async function streamRun(threadId, assistantId, onDelta) {
  const stream = await openai.beta.threads.runs.stream(threadId, { assistant_id: assistantId });
  stream.on('textDelta', (d) => d && d.value && onDelta(d.value));
  return new Promise((resolve, reject) => {
    stream.on('messageCompleted', () => resolve());
    stream.on('error', reject);
  });
}

module.exports = {
  getAssistantIdForUser,
  ensureThread,
  addUserMessage,
  streamRun,
};
