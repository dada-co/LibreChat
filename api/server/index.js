// Toggle with MAGIC_DEBUG=true
const MAGIC_DEBUG = String(process.env.MAGIC_DEBUG || '').toLowerCase() === 'true';
const red = (s, head = 10, tail = 6) =>
  !s ? '∅' : (s.length <= head + tail ? s : `${s.slice(0, head)}…${s.slice(-tail)}`);

// 1) Per-request summary
if (MAGIC_DEBUG) {
  app.use((req, _res, next) => {
    const cks = Object.keys(req.cookies || {});
    console.log('[req]', req.method, req.path, 'cookies:', cks);
    next();
  });
}

// 2) Bridge cookie -> Authorization (with logs)
app.use((req, _res, next) => {
  if (!req.headers.authorization) {
    const c = req.cookies || {};
    const t = c.jwt || c.token || c.accessToken;
    if (t) {
      req.headers.authorization = `Bearer ${t}`;
      if (MAGIC_DEBUG) {
        console.log('[bridge] set Authorization from cookie; jwt:', red(t));
      }
    } else if (MAGIC_DEBUG) {
      console.log('[bridge] no auth cookie present');
    }
  }
  next();
});

// 3) Log incoming /api/auth/refresh requests (what cookies we have)
if (MAGIC_DEBUG) {
  app.use('/api/auth', (req, _res, next) => {
    if (req.path.startsWith('/refresh')) {
      const c = req.cookies || {};
      console.log('[refresh] cookies:',
        Object.fromEntries(
          Object.entries(c).map(([k, v]) => [k, k === 'refreshToken' || k === 'jwt' ? red(v) : '…'])
        )
      );
    }
    next();
  });
}
