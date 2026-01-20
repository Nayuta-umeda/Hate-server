/**
 * いじめ密告所 - server
 * - data/db.json に保存（小規模向け）
 * - 画像/動画は「申請」→ 管理者が承認/却下
 */
import express from "express";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import cors from "cors";

const app = express();
app.use(express.json({ limit: "25mb" }));
app.use(cors({ origin: true, credentials: false }));

const PORT = process.env.PORT || 3000;
const API = "/api/ijime";

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin";
const ADMIN_TOKEN_SECRET = process.env.ADMIN_TOKEN_SECRET || "change-me";

const DB_PATH = path.join(process.cwd(), "data", "db.json");

function uid(prefix) { return prefix + crypto.randomBytes(10).toString("hex"); }
function nowISO() { return new Date().toISOString(); }

function readDB() {
  try {
    const raw = fs.readFileSync(DB_PATH, "utf-8");
    const db = JSON.parse(raw);
    db.threads ||= [];
    db.attachments ||= [];
    return db;
  } catch {
    return { threads: [], attachments: [] };
  }
}
function writeDB(db) {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), "utf-8");
}

function pruneViewEvents(thread) {
  const cutoff = Date.now() - 31 * 24 * 60 * 60 * 1000;
  thread.viewEvents = (thread.viewEvents || []).filter((iso) => {
    const t = Date.parse(iso);
    return Number.isFinite(t) && t >= cutoff;
  });
}

function pvCount(events, ms) {
  const now = Date.now();
  let c = 0;
  for (const iso of events || []) {
    const t = Date.parse(iso);
    if (!Number.isFinite(t)) continue;
    if (now - t <= ms) c++;
  }
  return c;
}

function sanitizeText(s, maxLen) {
  const t = String(s ?? "").replace(/\r/g, "");
  return t.length > maxLen ? t.slice(0, maxLen) : t;
}
function sanitizeTags(tags) {
  const out = [];
  const seen = new Set();
  for (const t of (Array.isArray(tags) ? tags : [])) {
    const v = sanitizeText(t, 24).trim();
    if (!v) continue;
    if (seen.has(v)) continue;
    seen.add(v);
    out.push(v);
    if (out.length >= 12) break;
  }
  return out;
}

function isDataUrl(s) { return typeof s === "string" && s.startsWith("data:"); }
function isAllowedMediaType(type) { return typeof type === "string" && (type.startsWith("image/") || type.startsWith("video/")); }

function signAdminToken() {
  const ts = Date.now().toString();
  const payload = `admin:${ts}`;
  const mac = crypto.createHmac("sha256", ADMIN_TOKEN_SECRET).update(payload).digest("hex");
  return Buffer.from(`${payload}:${mac}`).toString("base64url");
}
function verifyAdminToken(token) {
  try {
    const decoded = Buffer.from(token, "base64url").toString("utf-8");
    const parts = decoded.split(":");
    if (parts.length !== 3) return false;
    const [role, ts, mac] = parts;
    if (role !== "admin") return false;
    const payload = `${role}:${ts}`;
    const mac2 = crypto.createHmac("sha256", ADMIN_TOKEN_SECRET).update(payload).digest("hex");
    return crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(mac2));
  } catch {
    return false;
  }
}
function mustAdmin(req, res, next) {
  const tok = req.header("X-Admin-Token") || "";
  const ok = tok && verifyAdminToken(tok);
  if (!ok) return res.status(401).json({ error: "unauthorized" });
  return next();
}

// public
app.get(`${API}/ping`, (req, res) => res.json({ ok: true }));

app.get(`${API}/threads`, (req, res) => {
  const sort = String(req.query.sort || "new");
  const db = readDB();

  const threads = db.threads.map((t) => {
    pruneViewEvents(t);
    const pvDay = pvCount(t.viewEvents, 24 * 60 * 60 * 1000);
    const pvWeek = pvCount(t.viewEvents, 7 * 24 * 60 * 60 * 1000);
    const pvMonth = pvCount(t.viewEvents, 30 * 24 * 60 * 60 * 1000);
    const postCount = (t.posts || []).length;
    return {
      id: t.id,
      title: t.title,
      tags: t.tags || [],
      createdAt: t.createdAt,
      updatedAt: t.updatedAt,
      postCount,
      pvDay,
      pvWeek,
      pvMonth,
    };
  });

  const key =
    sort === "pv_day" ? "pvDay" :
    sort === "pv_week" ? "pvWeek" :
    sort === "pv_month" ? "pvMonth" :
    "updatedAt";

  threads.sort((a, b) => {
    if (key === "updatedAt") return String(b.updatedAt || b.createdAt).localeCompare(String(a.updatedAt || a.createdAt));
    const d = (b[key] || 0) - (a[key] || 0);
    if (d !== 0) return d;
    return String(b.updatedAt || b.createdAt).localeCompare(String(a.updatedAt || a.createdAt));
  });

  writeDB(db);
  res.json({ threads });
});

app.post(`${API}/threads`, (req, res) => {
  const title = sanitizeText(req.body?.title, 80).trim() || "(無題)";
  const body = sanitizeText(req.body?.body, 8000);
  const tags = sanitizeTags(req.body?.tags);
  const authorId = sanitizeText(req.body?.authorId, 64).trim() || "UNKNOWN";

  const db = readDB();

  const threadId = uid("T");
  const postId = uid("P");
  const ts = nowISO();

  const thread = {
    id: threadId,
    title,
    tags,
    creatorId: authorId,
    createdAt: ts,
    updatedAt: ts,
    viewEvents: [],
    posts: [
      {
        id: postId,
        authorId,
        createdAt: ts,
        updatedAt: ts,
        body,
      },
    ],
  };

  db.threads.push(thread);
  writeDB(db);

  res.json({ thread: { id: threadId, title, tags, createdAt: ts, updatedAt: ts, postCount: 1, pvDay: 0, pvWeek: 0, pvMonth: 0 } });
});

app.get(`${API}/threads/:id`, (req, res) => {
  const id = String(req.params.id || "");
  const viewerId = sanitizeText(req.query.viewerId, 64).trim() || "";

  const db = readDB();
  const thread = db.threads.find((t) => t.id === id);
  if (!thread) return res.status(404).json({ error: "not found" });

  pruneViewEvents(thread);
  const pvDay = pvCount(thread.viewEvents, 24 * 60 * 60 * 1000);
  const pvWeek = pvCount(thread.viewEvents, 7 * 24 * 60 * 60 * 1000);
  const pvMonth = pvCount(thread.viewEvents, 30 * 24 * 60 * 60 * 1000);

  const approved = db.attachments.filter((a) => a.threadId === id && a.status === "approved");
  const pendingMine = viewerId ? db.attachments.filter((a) => a.threadId === id && a.status === "pending" && a.requesterId === viewerId) : [];

  const posts = (thread.posts || []).map((p, idx) => {
    const approvedAttachments = approved
      .filter((a) => a.postId === p.id)
      .map((a) => ({ id: a.id, file: a.file }));
    const pendingMineCount = pendingMine.filter((a) => a.postId === p.id).length;

    return {
      id: p.id,
      no: idx + 1,
      authorId: p.authorId,
      createdAt: p.createdAt,
      updatedAt: p.updatedAt,
      body: p.body,
      approvedAttachments,
      pendingMineCount,
    };
  });

  writeDB(db);

  res.json({
    thread: {
      id: thread.id,
      title: thread.title,
      tags: thread.tags || [],
      createdAt: thread.createdAt,
      updatedAt: thread.updatedAt,
      pvDay,
      pvWeek,
      pvMonth,
      posts,
    },
  });
});

app.post(`${API}/threads/:id/posts`, (req, res) => {
  const id = String(req.params.id || "");
  const body = sanitizeText(req.body?.body, 8000);
  const authorId = sanitizeText(req.body?.authorId, 64).trim() || "UNKNOWN";

  const db = readDB();
  const thread = db.threads.find((t) => t.id === id);
  if (!thread) return res.status(404).json({ error: "not found" });

  const postId = uid("P");
  const ts = nowISO();
  thread.posts ||= [];
  thread.posts.push({
    id: postId,
    authorId,
    createdAt: ts,
    updatedAt: ts,
    body,
  });
  thread.updatedAt = ts;
  writeDB(db);

  res.json({ post: { id: postId } });
});

app.post(`${API}/threads/:id/view`, (req, res) => {
  const id = String(req.params.id || "");
  const db = readDB();
  const thread = db.threads.find((t) => t.id === id);
  if (!thread) return res.status(404).json({ error: "not found" });

  thread.viewEvents ||= [];
  thread.viewEvents.push(nowISO());
  pruneViewEvents(thread);
  writeDB(db);
  res.json({ ok: true });
});

app.patch(`${API}/threads/:id/tags`, (req, res) => {
  const id = String(req.params.id || "");
  const tags = sanitizeTags(req.body?.tags);

  const db = readDB();
  const thread = db.threads.find((t) => t.id === id);
  if (!thread) return res.status(404).json({ error: "not found" });

  const merged = new Set([...(thread.tags || []), ...tags]);
  thread.tags = Array.from(merged).slice(0, 12);
  thread.updatedAt = nowISO();
  writeDB(db);

  res.json({ thread: { id: thread.id, tags: thread.tags, updatedAt: thread.updatedAt } });
});

app.post(`${API}/attachments/request`, (req, res) => {
  const threadId = String(req.body?.threadId || "");
  const postId = String(req.body?.postId || "");
  const requesterId = sanitizeText(req.body?.requesterId, 64).trim() || "UNKNOWN";
  const f = req.body?.file || {};

  const file = {
    name: sanitizeText(f.name, 180),
    type: sanitizeText(f.type, 120),
    size: Number.isFinite(Number(f.size)) ? Number(f.size) : 0,
    dataUrl: f.dataUrl,
  };

  if (!threadId || !postId) return res.status(400).json({ error: "bad_request" });
  if (!isAllowedMediaType(file.type)) return res.status(400).json({ error: "type" });
  if (!isDataUrl(file.dataUrl)) return res.status(400).json({ error: "dataurl" });

  const db = readDB();
  const thread = db.threads.find((t) => t.id === threadId);
  if (!thread) return res.status(404).json({ error: "thread_not_found" });
  const post = (thread.posts || []).find((p) => p.id === postId);
  if (!post) return res.status(404).json({ error: "post_not_found" });

  const att = {
    id: uid("A"),
    threadId,
    postId,
    requesterId,
    status: "pending",
    createdAt: nowISO(),
    reviewedAt: "",
    note: "",
    file,
  };

  db.attachments.push(att);
  writeDB(db);

  res.json({ attachment: { id: att.id, status: att.status, createdAt: att.createdAt } });
});

// admin
app.post(`${API}/admin/login`, (req, res) => {
  const password = String(req.body?.password || "");
  if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: "invalid" });
  const token = signAdminToken();
  res.json({ ok: true, name: "ADMIN", token });
});

app.get(`${API}/admin/threads`, mustAdmin, (req, res) => {
  const db = readDB();
  res.json({ threads: db.threads });
});

app.get(`${API}/admin/attachments`, mustAdmin, (req, res) => {
  const status = String(req.query.status || "pending");
  const db = readDB();
  const mapThreadTitle = new Map(db.threads.map((t) => [t.id, t.title]));
  const attachments = db.attachments
    .filter((a) => (status ? a.status === status : true))
    .map((a) => ({
      ...a,
      threadTitle: mapThreadTitle.get(a.threadId) || "",
    }))
    .sort((a, b) => String(b.createdAt || "").localeCompare(String(a.createdAt || "")));

  res.json({ attachments });
});

app.post(`${API}/admin/attachments/review`, mustAdmin, (req, res) => {
  const attachmentId = String(req.body?.attachmentId || "");
  const action = String(req.body?.action || "");
  const note = sanitizeText(req.body?.note, 800);

  const db = readDB();
  const att = db.attachments.find((a) => a.id === attachmentId);
  if (!att) return res.status(404).json({ error: "not_found" });

  if (att.status !== "pending") return res.status(400).json({ error: "already_reviewed" });
  if (action !== "approve" && action !== "reject") return res.status(400).json({ error: "bad_action" });

  att.status = action === "approve" ? "approved" : "rejected";
  att.note = note;
  att.reviewedAt = nowISO();
  writeDB(db);

  res.json({ attachment: att });
});

app.get("/", (req, res) => res.send("ok"));
app.listen(PORT, () => console.log(`listening :${PORT}`));
