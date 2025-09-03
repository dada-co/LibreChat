const OpenAI = require('openai');
const fetch = require('node-fetch');
const { logger } = require('~/config');

const logFetch = async (url, init = {}) => {
  const urlString = typeof url === 'string' ? url : url?.toString();
  if (urlString.includes('/responses')) {
    const method = init.method || 'GET';
    const headers =
      init.headers instanceof fetch.Headers
        ? Object.fromEntries(init.headers.entries())
        : { ...(init.headers || {}) };

    if (headers.Authorization) {
      headers.Authorization = '***';
    }

    if (headers['api-key']) {
      headers['api-key'] = '***';
    }

    let body = init.body;
    if (body && typeof body !== 'string') {
      try {
        body = JSON.stringify(body);
      } catch {
        body = '[unserializable body]';
      }
    }

    logger.info(`[Responses API] ${method} ${urlString}`);
    logger.debug(`[Responses API Headers] ${JSON.stringify(headers)}`);
    if (body) {
      logger.debug(`[Responses API Body] ${body}`);
    }
  }
  return fetch(url, init);
};

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
  fetch: logFetch,
});

module.exports = { openai };
