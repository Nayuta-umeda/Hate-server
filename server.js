import express from "express";
import helmet from "helmet";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// ---- Security-ish defaults (quiet, no server banners) ----
app.disable("x-powered-by");
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        // allow same-origin only
        "script-src": ["'self'"]
      }
    },
    crossOriginEmbedderPolicy: false // keep simple for audio on some browsers
  })
);

app.use(express.json({ limit: "32kb" }));

// ---- Data storage ----
const DATA_DIR = path.join(__dirname, "..", "data");
const DATA_PATH = path.join(DATA_DIR, "posts.json");

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function loadPosts() {
  try {
    ensureDataDir();
    if (!fs.existsSync(DATA_PATH)) return [];
    const raw = fs.readFileSync(DATA_PATH, "utf-8");
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed;
  } catch {
    return [];
  }
}

function savePosts(posts) {
  ensureDataDir();
  // write atomically
  const tmp = DATA_PATH + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(posts, null, 0), "utf-8");
  fs.renameSync(tmp, DATA_PATH);
}

let posts = loadPosts();
let nextId = posts.length ? (posts[posts.length - 1].id + 1) : 1;

// keep last N posts to prevent unbounded growth
const MAX_POSTS = 300;

// ---- Simple IP rate limit (best-effort) ----
const rl = new Map();
const POST_COOLDOWN_MS = 2500;

function ipOf(req) {
  // If behind proxy, set trust proxy as needed. Here: direct access.
  return req.socket?.remoteAddress || "unknown";
}

function canPost(ip) {
  const now = Date.now();
  const prev = rl.get(ip) || 0;
  if (now - prev < POST_COOLDOWN_MS) return false;
  rl.set(ip, now);
  return true;
}

function normalizeText(s) {
  // Normalize newlines, strip dangerous control chars (keep \n, \t)
  return String(s)
    .replace(/\r\n?/g, "\n")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .trim();
}

// ---- API ----
app.get("/api/posts", (req, res) => {
  // Optional: ?since=<unix_ms>
  const since = Number(req.query.since || 0);
  if (Number.isFinite(since) && since > 0) {
    const newer = posts.filter((p) => p.ts > since);
    return res.json({ ok: true, posts: newer, serverTime: Date.now() });
  }
  res.json({ ok: true, posts, serverTime: Date.now() });
});

app.post("/api/posts", (req, res) => {
  const ip = ipOf(req);
  if (!canPost(ip)) {
    return res.status(429).json({ ok: false, error: "too_fast" });
  }

  const name = normalizeText(req.body?.name ?? "");
  const mail = normalizeText(req.body?.mail ?? "");
  const body = normalizeText(req.body?.body ?? "");

  // Validation (keep simple)
  const finalName = name ? name.slice(0, 24) : "名無しさん";
  const finalMail = mail.slice(0, 40);
  const finalBody = body.slice(0, 800);

  if (!finalBody) {
    return res.status(400).json({ ok: false, error: "empty" });
  }

  // Small privacy nudge: reject extremely suspicious payload sizes
  if (finalBody.length > 800) {
    return res.status(400).json({ ok: false, error: "too_long" });
  }

  const post = {
    id: nextId++,
    ts: Date.now(),
    name: finalName,
    mail: finalMail,
    body: finalBody
  };

  posts.push(post);
  if (posts.length > MAX_POSTS) posts = posts.slice(posts.length - MAX_POSTS);

  try {
    savePosts(posts);
  } catch {
    // If persistence fails, still keep in-memory; client doesn't need details.
  }

  res.json({ ok: true, post });
});

// ---- Static files ----
const PUBLIC_DIR = path.join(__dirname, "..", "public");
app.use(express.static(PUBLIC_DIR, { etag: true, maxAge: "1h" }));

app.get("/healthz", (_req, res) => res.type("text").send("ok"));

const PORT = Number(process.env.PORT || 8787);
app.listen(PORT, "0.0.0.0", () => {
  // Intentionally quiet: do not print identifying banners.
  console.log("ready");
});
