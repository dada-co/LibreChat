// api/server/index.js
// Express server that: (a) handles magic-link auth, (b) exposes tiny API,
// and (c) serves the real client build (Vite/Next/CRA) when present.

const express = require("express");
const path = require("path");
const fs = require("fs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");

// ---------- basic app ----------
const app = express();
app.set("trust proxy", 1); // Heroku/Proxies
app.use(express.json());
app.use(cookieParser());

// ---------- tiny logger ----------
const LOG = {
  info: (...a) => console.log(new Date().toISOString(), "info ", ":", ...a),
  warn: (...a) => console.warn(new Date().toISOString(), "warn ", ":", ...a),
  error: (...a) => console.error(new Date().toISOString(), "error", ":", ...a),
};

// ---------- security & env ----------
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
const MAGIC_SECRET = process.env.MAGIC_SECRET || JWT_SECRET;

const ACCESS_TTL_SEC = Number(process.env.ACCESS_TTL_SEC || 60 * 60); // 1h
const REFRESH_TTL_SEC = Number(process.env.REFRESH_TTL_SEC || 7 * 24 * 60 * 60); // 7d

// In-memory refresh store (ephemeral on Heroku dyno restarts; OK for demo)
let refreshHashes = [];

// ---------- helpers ----------
const signAccess = (sub) =>
  jwt.sign({ sub, typ: "access" }, JWT_SECRET, { algorithm: "HS256", expiresIn: ACCESS_TTL_SEC });
const signRefresh = (sub) =>
  jwt.sign({ sub, typ: "refresh" }, JWT_SECRET, { algorithm: "HS256", expiresIn: REFRESH_TTL_SEC });

function setAuthCookies(res, { access, refresh }) {
  // Keep names matching your logs: jwt, token, accessToken, refreshToken
  const cookieOpts = {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    path: "/",
  };
  res.cookie("jwt", access, cookieOpts);
  res.cookie("token", access, cookieOpts);
  res.cookie("accessToken", access, cookieOpts);
  res.cookie("refreshToken", refresh, cookieOpts);
}

function hash(str) {
  // super-light “hash” to avoid pulling in bcrypt again; good enough for demo
  // not for production!
  const crypto = require("crypto");
  return crypto.createHash("sha256").update(String(str)).digest("hex");
}

// Middleware: forward cookie token as Authorization header for API calls
app.use((req, res, next) => {
  const skip = req.path.startsWith("/api/auth/refresh");
  if (!skip) {
    const tok = req.cookies?.jwt || req.cookies?.token || req.cookies?.accessToken;
    if (tok && !req.headers.authorization) req.headers.authorization = `Bearer ${tok}`;
    LOG.info("[bridge] Authorization set from cookie");
  } else {
    LOG.info("[bridge] SKIP on /api/auth/refresh");
  }
  next();
});

// ---------- demo API ----------
app.get("/api/banner", (_req, res) => res.status(200).send(""));

app.get("/api/config", (_req, res) => {
  res.json({
    appName: "Own Chat",
    auth: { magicLink: true },
  });
});

app.get("/api/user", (req, res) => {
  try {
    const auth = req.headers.authorization?.split(" ")[1];
    if (!auth) return res.json({ id: "anon", email: null, role: "guest" });
    const payload = jwt.verify(auth, JWT_SECRET);
    // In your demo we just map sub -> a fake user
    return res.json({
      id: payload.sub || "68a9bb16aa1ca26aef9e9524",
      email: "demo1@no-mail.invalid",
      role: "user",
    });
  } catch {
    return res.json({ id: "anon", email: null, role: "guest" });
  }
});

// Optional refresh endpoint (no-op demo)
app.post("/api/auth/refresh", (_req, res) => {
  // In real life you'd verify refresh token and issue new access.
  // We keep it simple because the app already works fine without it.
  res.status(302).send("ok");
});

// ---------- Magic link flow ----------
/**
 * 1) User hits /m/:token where :token is a JWT signed with MAGIC_SECRET.
 * 2) We verify and mint access+refresh cookies, then redirect to /m/signed.
 */
app.get("/m/:token", (req, res) => {
  LOG.info("[req] GET", req.originalUrl, "cookies:", Object.keys(req.cookies || []));
  const token = req.params.token;
  LOG.info("[magic] GET /m/:token hit param token");

  try {
    const payload = jwt.verify(token, MAGIC_SECRET, { algorithms: ["HS256"] });
    LOG.info("[magic] token verified", {
      aud: payload.aud || "magic-link",
      sub: payload.sub,
      iat: payload.iat,
      exp: payload.exp,
    });

    // Lookup user by sub; here we just demo a single user
    const user = {
      id: payload.sub || "68a9bb16aa1ca26aef9e9524",
      email: "demo1@no-mail.invalid",
      role: "user",
    };
    LOG.info("[magic] user found", user);

    const access = signAccess(user.id);
    const refresh = signRefresh(user.id);
    LOG.info("[magic] signed tokens { access: ****, refresh: **** }");

    // "Store" refresh hash (demo)
    const h = hash(refresh);
    const before = refreshHashes.length;
    if (!refreshHashes.includes(h)) refreshHashes.push(h);
    LOG.info("[magic] saved refresh hash", {
      listLenBefore: before,
      listLenAfter: refreshHashes.length,
      hash: h.length > 14 ? `${h.slice(0, 6)}…${h.slice(-6)}` : h,
    });

    setAuthCookies(res, { access, refresh });
    LOG.info("[magic] set cookies", {
      cookieNames: ["jwt", "token", "accessToken", "refreshToken"],
      sameSite: "None",
      secure: true,
    });

    return res.redirect(302, "/m/signed");
  } catch (err) {
    LOG.warn("[magic] invalid token:", err?.message || err);
    return res.status(401).send("invalid_token");
  }
});

// Tiny confirmation page (kept for debugging)
app.get("/m/signed", (_req, res) => {
  res
    .status(200)
    .send(
      `<!doctype html><meta charset="utf-8"/><title>Signed</title><style>body{font-family:ui-serif,Georgia,serif;padding:24px;font-size:40px}</style><div>Signed in ✔</div>`
    );
});

// ---------- Static client (real UI) ----------
/**
 * We try to find a built frontend automatically.
 * You can override with FRONTEND_DIR (absolute or relative to repo root).
 */
function resolveClientDir() {
  const custom = process.env.FRONTEND_DIR;
  const candidates = [
    custom && path.resolve(custom),
    path.resolve(__dirname, "../../web/dist"),
    path.resolve(__dirname, "../../client/dist"),
    path.resolve(__dirname, "../../frontend/dist"),
    path.resolve(__dirname, "../../app/dist"),
    path.resolve(__dirname, "../../dist"),
    path.resolve(__dirname, "../public"), // fallback to server/public
    path.resolve(__dirname, "../../public"),
  ].filter(Boolean);

  for (const p of candidates) {
    if (fs.existsSync(p) && fs.existsSync(path.join(p, "index.html"))) {
      return p;
    }
  }
  return null;
}

const CLIENT_DIR = resolveClientDir();
if (CLIENT_DIR) {
  LOG.info(`[static] Serving client from: ${CLIENT_DIR}`);
  app.use(
    express.static(CLIENT_DIR, {
      index: false,
      maxAge: "1y",
      setHeaders: (res, filePath) => {
        // never cache index.html
        if (filePath.endsWith("index.html")) {
          res.setHeader("Cache-Control", "no-store");
        }
      },
    })
  );

  // Service worker & workbox helpers if present
  for (const p of ["sw.js", "workbox-*.js", "manifest.webmanifest"]) {
    app.get(`/${p}`, (req, res, next) => {
      const file = path.join(CLIENT_DIR, req.path);
      if (fs.existsSync(file)) return res.sendFile(file);
      return next();
    });
  }

  // App routes -> index.html
  const SPA_ROUTES = [
    "/",
    "/c/new",
    "/c/:id",
    "/login",
    "/settings",
    "/chat",
    "/app",
    "/embed/*",
  ];

  app.get(SPA_ROUTES, (_req, res) => {
    res.sendFile(path.join(CLIENT_DIR, "index.html"));
  });

  // Catch-all (but leave /api/* and /m/* to their handlers)
  app.get("*", (req, res, next) => {
    if (req.path.startsWith("/api/") || req.path.startsWith("/m/")) return next();
    const indexPath = path.join(CLIENT_DIR, "index.html");
    if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
    return next();
  });
} else {
  LOG.warn("[static] No client build found. Serving placeholder UI.");

  // Minimal placeholder so the app is still usable
  app.get("/", async (req, res) => {
    // Try to show who we think you are
    let user = { id: "anon", email: null, role: "guest" };
    try {
      const tok = req.cookies?.jwt || req.cookies?.token || req.cookies?.accessToken;
      if (tok) {
        const payload = jwt.verify(tok, JWT_SECRET);
        user = {
          id: payload.sub || "68a9bb16aa1ca26aef9e9524",
          email: "demo1@no-mail.invalid",
          role: "user",
        };
      }
    } catch {}
    const json = JSON.stringify(user, null, 2);
    res
      .status(200)
      .send(`<!doctype html>
<meta charset="utf-8"/>
<title>Own Chat</title>
<style>
  body{font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans;
       padding:24px;line-height:1.5}
  pre{background:#f3f3f3;padding:16px;border-radius:12px;overflow:auto}
  a{color:#2563eb;text-decoration-thickness:2px}
</style>
<h1>Own Chat</h1>
<p>This is a minimal placeholder UI served by <code>api/server/index.js</code>.</p>
<p><a href="/m/signed">Test: signed page</a></p>
<pre>${json}</pre>`);
  });
}

// --------------- errors ---------------
app.use((err, _req, res, _next) => {
  LOG.error("Unhandled error:", err?.message || err);
  res.status(500).send("server_error");
});

// --------------- start ---------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => LOG.info(`Server listening on :${PORT}`));
