const uap = require('ua-parser-js');
const { ViolationTypes } = require('librechat-data-provider');
const { handleError } = require('@librechat/api');
const { logger } = require('@librechat/data-schemas');
const { logViolation } = require('../../cache');

/**
 * Converts the comma-separated allow list into an array of matcher functions.
 * Supports simple substring matches as well as regex patterns wrapped in `/`.
 *
 * @param {string | undefined} allowList
 * @returns {(ua: string) => boolean}
 */
function buildAllowListMatcher(allowList) {
  if (!allowList) {
    return () => false;
  }

  const matchers = allowList
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((pattern) => {
      if (pattern.startsWith('/') && pattern.endsWith('/') && pattern.length > 2) {
        try {
          const regex = new RegExp(pattern.slice(1, -1));
          return (ua) => regex.test(ua);
        } catch (error) {
          logger.warn(`Invalid regex in ALLOW_NON_BROWSER_USER_AGENTS: ${pattern}`, error);
        }
      }
      return (ua) => ua.includes(pattern);
    })
    .filter(Boolean);

  if (matchers.length === 0) {
    return () => false;
  }

  return (ua) => matchers.some((matcher) => matcher(ua));
}

/**
 * Middleware to parse User-Agent header and check if it's from a recognized browser.
 * If the User-Agent is not recognized as a browser, logs a violation and sends an error response.
 *
 * @function
 * @async
 * @param {Object} req - Express request object.
 * @param {Object} res - Express response object.
 * @param {Function} next - Express next middleware function.
 * @returns {void} Sends an error response if the User-Agent is not recognized as a browser.
 *
 * @example
 * app.use(uaParser);
 */
async function uaParser(req, res, next) {
  const { NON_BROWSER_VIOLATION_SCORE: score = 20, ALLOW_NON_BROWSER_USER_AGENTS } = process.env;
  const userAgent = req.headers['user-agent'] ?? '';
  const ua = uap(userAgent);
  const isAllowedNonBrowser = buildAllowListMatcher(ALLOW_NON_BROWSER_USER_AGENTS);

  if (!ua.browser.name && !isAllowedNonBrowser(userAgent)) {
    const type = ViolationTypes.NON_BROWSER;
    await logViolation(req, res, type, { type }, score);
    return handleError(res, { message: 'Illegal request' });
  }
  next();
}

module.exports = uaParser;
