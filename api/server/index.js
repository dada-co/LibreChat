// api/server/index.js
require('dotenv').config();
const fs = require('fs');
const path = require('path');
require('module-alias')({ base: path.resolve(__dirname, '..') });

const cors = require('cors');
const axios = require('axios');
const express = require('express');
const passport = require('passport');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const mongoSanitize = require('express-mongo-sanitize');

const { logger } = require('@librechat/data-schemas');
const { isEnabled, ErrorController } = require('@librechat/api');
const { connectDb, indexSync } = require('~/db');

const validateImageRequest = require('./middleware/validateImageRequest');
const { jwtLogin, ldapLogin, passportLogin } = require('~/strategies');
const { checkMigrations } = require('./services/start/migration');
const initializeMCPs = require('./services/initializeMCPs');
const configureSocialLogins = require('./socialLogins');
const AppService = require('./services/AppService');
const staticCache = require('./utils/staticCache');
const noIndex = require('./middleware/noIndex');
const routes = require('./routes');

const {
  PORT,
  HOST,
  ALLOW_SOCIAL_LOGIN,
  DISABLE_COMPRESSION,
  TRUST_PROXY,
  PUBLIC_URL,
} = process.env ?? {};

const port = Number.isNaN(Number(PORT)) ? 3080 : Number(PORT);
const host = HOST || (process.env.DYNO ? '0.0.0.0' : 'localhost');
const trusted_proxy = Number(TRUST_PROXY) || 1;

const app = express();

const startServer = async () => {
  if (typeof Bun !== 'undefined') {
    axios.defaults.headers.common['Accept-Encoding'] = 'gzip';
  }

  await connectDb();
  logger.info('Connected to MongoDB');
  indexSync().catch((err) => logger.error('[indexSync] Background sync failed:', err));

  app.disable('x-powered-by');
  app.set('trust proxy', trusted_proxy);

  await AppService(app);

  const indexPath = path.join(app.locals.paths.dist, 'index.html');
  const indexHTML = fs.readFileSync(indexPath, 'utf8');

  app.get('/health', (_req, res) => res.status(200).send('OK'));

  /* Middleware */
  app.use(noIndex);
  app.use(express.json({ limit: '3mb' }));
  app.use(express.urlencoded({ extended: true, limit: '3mb' }));
  app.use(mongoSanitize());
  app.use(cookieParser());

  app.use(
    cors({
      origin: PUBLIC_URL || true,
      credentials: true,
    }),
  );

  // Only trust the HttpOnly 'jwt' cookie (not legacy names)
  app.use((req, _res, next) => {
    if (!req.headers.authorization) {
      const t = req.cookies?.jwt;
      if (t) req.headers.authorization = `Bearer ${t}`;
    }
    next();
  });

  if (!isEnabled(DISABLE_COMPRESSION)) {
    app.use(compression());
  }

  // Static assets
  app.use(staticCache(app.locals.paths.dist));
  app.use(staticCache(app.locals.paths.fonts));
  app.use(staticCache(app.locals.paths.assets));

  /* Passport */
  app.use(passport.initialize());
  passport.use(jwtLogin());
  passport.use(passportLogin());
  if (process.env.LDAP_URL && process.env.LDAP_USER_SEARCH_BASE) {
    passport.use(ldapLogin);
  }
  if (isEnabled(ALLOW_SOCIAL_LOGIN)) {
    await configureSocialLogins(app);
  }

  /* Load custom routes defensively */
  let magicRoutes = express.Router();
  let adminUsers = express.Router();

  try {
    magicRoutes = require(path.join(__dirname, '..', 'routes', 'magic'));
    logger.info('[routes] loaded /m (magic)');
  } catch (e) {
    console.error('[routes] failed to load /m (magic):', e && e.stack ? e.stack : e);
  }

  try {
    adminUsers = require(path.join(__dirname, '..', 'routes', 'admin.users'));
    logger.info('[routes] loaded /api/admin');
  } catch (e) {
    console.error('[routes] failed to load /api/admin:', e && e.stack ? e.stack : e);
  }

  /* Routes (magic FIRST) */
  app.use('/', magicRoutes);

  app.use('/oauth', routes.oauth);
  app.use('/api/admin', adminUsers);
  app.use('/api/auth', routes.auth);
  app.use('/api/actions', routes.actions);
  app.use('/api/keys', routes.keys);
  app.use('/api/user', routes.user);
  app.use('/api/search', routes.search);
  app.use('/api/edit', routes.edit);
  app.use('/api/messages', routes.messages);
  app.use('/api/convos', routes.convos);
  app.use('/api/presets', routes.presets);
  app.use('/api/prompts', routes.prompts);
  app.use('/api/categories', routes.categories);
  app.use('/api/tokenizer', routes.tokenizer);
  app.use('/api/endpoints', routes.endpoints);
  app.use('/api/balance', routes.balance);
  app.use('/api/models', routes.models);
  app.use('/api/plugins', routes.plugins);
  app.use('/api/config', routes.config);
  app.use('/api/assistants', routes.assistants);
  app.use('/api/files', await routes.files.initialize());
  app.use('/images/', validateImageRequest, routes.staticRoute);
  app.use('/api/share', routes.share);
  app.use('/api/roles', routes.roles);
  app.use('/api/agents', routes.agents);
  app.use('/api/banner', routes.banner);
  app.use('/api/memories', routes.memories);
  app.use('/api/permissions', routes.accessPermissions);
  app.use('/api/tags', routes.tags);
  app.use('/api/mcp', routes.mcp);

  app.use(ErrorController);

  // SPA catch-all – keep LAST
  app.use((req, res) => {
    res.set({
      'Cache-Control': process.env.INDEX_CACHE_CONTROL || 'no-cache, no-store, must-revalidate',
      Pragma: process.env.INDEX_PRAGMA || 'no-cache',
      Expires: process.env.INDEX_EXPIRES || '0',
    });

    const lang = req.cookies.lang || req.headers['accept-language']?.split(',')[0] || 'en-US';
    const saneLang = lang.replace(/"/g, '&quot;');
    const updatedIndexHtml = indexHTML.replace(/lang="en-US"/g, `lang="${saneLang}"`);
    res.type('html');
    res.send(updatedIndexHtml);
  });

  app.listen(port, host, () => {
    const where = host === '0.0.0.0' ? `http://localhost:${port}` : `http://${host}:${port}`;
    logger.info(`Server listening at ${where}`);
    initializeMCPs(app).then(() => checkMigrations());
  });
};

startServer();

let messageCount = 0;
process.on('uncaughtException', (err) => {
  if (!err.message.includes('fetch failed')) {
    logger.error('There was an uncaught error:', err);
  }
  if (err.message.includes('abort')) return logger.warn('There was an uncatchable AbortController error.');
  if (err.message.includes('GoogleGenerativeAI')) {
    return logger.warn('GoogleGenerativeAI errors cannot be caught due to an upstream issue.');
  }
  if (err.message.includes('fetch failed')) {
    if (messageCount === 0) {
      logger.warn('Meilisearch error, search will be disabled');
      messageCount++;
    }
    return;
  }
  if (err.message.includes('OpenAIError') || err.message.includes('ChatCompletionMessage')) {
    logger.error('An uncaught OpenAI error may be due to reverse-proxy/stream config or an upstream bug.');
    return;
  }
  process.exit(1);
});

module.exports = app;
