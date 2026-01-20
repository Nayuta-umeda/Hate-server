import express from "express";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import cors from "cors";

const app = express();
app.use(express.json({ limit: "25mb" }));
app.use(cors({ origin: true, credentials: false }));

const PORT = process.env.PORT || 3000;
const API = "/api/diary";

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
    db.verifyRequests ||= [];
    db.verifiedUsers ||= {};
    return db;
  } catch {
    return { threads: [], attachments: [], verifyRequests: [], verifiedUsers: {} };
  }
}
function writeDB(db) {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), "utf-8");
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
function isImageType(type){ return typeof type === "string" && type.startsWith("image/"); }

function pruneLikeEvents(thread) {
  const cutoff = Date.now() - 31 * 24 * 60 * 60 * 1000;
  const out = {};
  for (const [k, iso] of Object.entries(thread.likesByUser || {})) {
    const t = Date.parse(iso);
    if (Number.isFinite(t) && t >= cutoff) out[k] = iso;
  }
  thread.likesByUser = out;
}
function likeCount(thread, ms) {
  const now = Date.now();
  let c = 0;
  for (const iso of Object.values(thread.likesByUser || {})) {
    const t = Date.parse(iso);
    if (!Number.isFinite(t)) continue;
    if (now - t <= ms) c++;
  }
  return c;
}

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

function threadSummary(t){
  pruneLikeEvents(t);
  const likeDay = likeCount(t, 24*60*60*1000);
  const likeWeek = likeCount(t, 7*24*60*60*1000);
  const likeMonth = likeCount(t, 30*24*60*60*1000);
  return {
    id: t.id,
    title: t.title,
    tags: t.tags || [],
    createdAt: t.createdAt,
    updatedAt: t.updatedAt,
    postCount: (t.posts || []).length,
    likeDay, likeWeek, likeMonth,
  };
}

function dbIsVerified(userId){
  const d = readDB();
  return !!d.verifiedUsers?.[userId];
}

app.get(`${API}/ping`, (req, res) => res.json({ ok: true }));

app.get(`${API}/threads`, (req, res) => {
  const sort = String(req.query.sort || "new");
  const db = readDB();

  const threads = db.threads
    .filter(t => !t.hidden)
    .map((t) => threadSummary(t));

  const key =
    sort === "like_day" ? "likeDay" :
    sort === "like_week" ? "likeWeek" :
    sort === "like_month" ? "likeMonth" :
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
    hidden: false,
    likesByUser: {},
    posts: [{ id: postId, authorId, createdAt: ts, updatedAt: ts, body }],
  };

  db.threads.push(thread);
  writeDB(db);

  res.json({ thread: threadSummary(thread) });
});

app.get(`${API}/threads/:id`, (req, res) => {
  const id = String(req.params.id || "");
  const viewerId = sanitizeText(req.query.viewerId, 64).trim() || "";

  const db = readDB();
  const thread = db.threads.find((t) => t.id === id);
  if (!thread || thread.hidden) return res.status(404).json({ error: "not found" });

  pruneLikeEvents(thread);
  const likeDay = likeCount(thread, 24*60*60*1000);
  const likeWeek = likeCount(thread, 7*24*60*60*1000);
  const likeMonth = likeCount(thread, 30*24*60*60*1000);

  const approved = db.attachments.filter((a) => a.threadId === id && a.status === "approved");
  const pendingMine = viewerId ? db.attachments.filter((a) => a.threadId === id && a.status === "pending" && a.requesterId === viewerId) : [];

  const posts = (thread.posts || []).map((p, idx) => {
    const approvedAttachments = approved.filter((a) => a.postId === p.id).map((a) => ({ id: a.id, file: a.file }));
    const pendingMineCount = pendingMine.filter((a) => a.postId === p.id).length;

    return { id: p.id, no: idx+1, authorId: p.authorId, createdAt: p.createdAt, updatedAt: p.updatedAt, body: p.body, approvedAttachments, pendingMineCount };
  });

  writeDB(db);

  res.json({ thread: { id: thread.id, title: thread.title, tags: thread.tags || [], createdAt: thread.createdAt, updatedAt: thread.updatedAt, likeDay, likeWeek, likeMonth, posts } });
});

app.post(`${API}/threads/:id/posts`, (req, res) => {
  const id = String(req.params.id || "");
  const body = sanitizeText(req.body?.body, 8000);
  const authorId = sanitizeText(req.body?.authorId, 64).trim() || "UNKNOWN";

  const db = readDB();
  const thread = db.threads.find((t) => t.id === id);
  if (!thread || thread.hidden) return res.status(404).json({ error: "not found" });

  const postId = uid("P");
  const ts = nowISO();
  thread.posts ||= [];
  thread.posts.push({ id: postId, authorId, createdAt: ts, updatedAt: ts, body });
  thread.updatedAt = ts;
  writeDB(db);

  res.json({ post: { id: postId } });
});

app.patch(`${API}/threads/:id/tags`, (req, res) => {
  const id = String(req.params.id || "");
  const tags = sanitizeTags(req.body?.tags);

  const db = readDB();
  const thread = db.threads.find((t) => t.id === id);
  if (!thread || thread.hidden) return res.status(404).json({ error: "not found" });

  const merged = new Set([...(thread.tags || []), ...tags]);
  thread.tags = Array.from(merged).slice(0, 12);
  thread.updatedAt = nowISO();
  writeDB(db);

  res.json({ thread: { id: thread.id, tags: thread.tags, updatedAt: thread.updatedAt } });
});

app.post(`${API}/threads/:id/like`, (req, res) => {
  const id = String(req.params.id || "");
  const userId = sanitizeText(req.body?.userId, 64).trim() || "";
  if (!userId) return res.status(400).json({ error: "bad_request" });

  const db = readDB();
  const thread = db.threads.find((t) => t.id === id);
  if (!thread || thread.hidden) return res.status(404).json({ error: "not found" });

  pruneLikeEvents(thread);
  thread.likesByUser ||= {};
  if (thread.likesByUser[userId]) return res.json({ ok: true, already: true });

  thread.likesByUser[userId] = nowISO();
  thread.updatedAt = nowISO();
  writeDB(db);
  res.json({ ok: true });
});

app.get(`${API}/users/:id/verify`, (req, res) => {
  const userId = sanitizeText(req.params.id, 64).trim() || "";
  const db = readDB();
  const verified = !!db.verifiedUsers?.[userId];
  res.json({ verified });
});

app.post(`${API}/verify/request`, (req, res) => {
  const userId = sanitizeText(req.body?.userId, 64).trim() || "UNKNOWN";
  const f = req.body?.file || {};

  const file = { name: sanitizeText(f.name, 180), type: sanitizeText(f.type, 120), size: Number.isFinite(Number(f.size)) ? Number(f.size) : 0, dataUrl: f.dataUrl };
  if (!isImageType(file.type)) return res.status(400).json({ error: "type" });
  if (!isDataUrl(file.dataUrl)) return res.status(400).json({ error: "dataurl" });

  const db = readDB();
  const reqId = uid("V");
  const vr = { id: reqId, userId, status:"pending", createdAt: nowISO(), reviewedAt:"", note:"", file };
  db.verifyRequests.push(vr);
  writeDB(db);
  res.json({ ok:true, request:{ id: vr.id, status: vr.status } });
});

app.post(`${API}/attachments/request`, (req, res) => {
  const threadId = String(req.body?.threadId || "");
  const postId = String(req.body?.postId || "");
  const requesterId = sanitizeText(req.body?.requesterId, 64).trim() || "UNKNOWN";
  const f = req.body?.file || {};

  const file = { name: sanitizeText(f.name, 180), type: sanitizeText(f.type, 120), size: Number.isFinite(Number(f.size)) ? Number(f.size) : 0, dataUrl: f.dataUrl };
  if (!threadId || !postId) return res.status(400).json({ error: "bad_request" });
  if (!dbIsVerified(requesterId)) return res.status(403).json({ error: "not_verified" });
  if (!isAllowedMediaType(file.type)) return res.status(400).json({ error: "type" });
  if (!isDataUrl(file.dataUrl)) return res.status(400).json({ error: "dataurl" });

  const db = readDB();
  const thread = db.threads.find((t) => t.id === threadId);
  if (!thread || thread.hidden) return res.status(404).json({ error: "thread_not_found" });
  const post = (thread.posts || []).find((p) => p.id === postId);
  if (!post) return res.status(404).json({ error: "post_not_found" });

  const att = { id: uid("A"), threadId, postId, requesterId, status:"pending", createdAt: nowISO(), reviewedAt:"", note:"", file };
  db.attachments.push(att);
  writeDB(db);
  res.json({ ok:true, attachment:{ id: att.id, status: att.status } });
});

app.post(`${API}/admin/login`, (req, res) => {
  const password = String(req.body?.password || "");
  if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: "invalid" });
  res.json({ ok:true, name:"ADMIN", token: signAdminToken() });
});

app.get(`${API}/admin/threads`, mustAdmin, (req, res) => {
  const db = readDB();
  res.json({ threads: db.threads });
});

app.post(`${API}/admin/thread/hide`, mustAdmin, (req, res) => {
  const threadId = String(req.body?.threadId || "");
  const hide = !!req.body?.hide;

  const db = readDB();
  const t = db.threads.find(x => x.id === threadId);
  if (!t) return res.status(404).json({ error: "not_found" });
  t.hidden = hide;
  t.updatedAt = nowISO();
  writeDB(db);
  res.json({ ok:true });
});

app.post(`${API}/admin/thread/delete`, mustAdmin, (req, res) => {
  const threadId = String(req.body?.threadId || "");
  const db = readDB();
  db.threads = db.threads.filter(t => t.id !== threadId);
  db.attachments = db.attachments.filter(a => a.threadId !== threadId);
  writeDB(db);
  res.json({ ok:true });
});

app.post(`${API}/admin/post/delete`, mustAdmin, (req, res) => {
  const threadId = String(req.body?.threadId || "");
  const postId = String(req.body?.postId || "");

  const db = readDB();
  const t = db.threads.find(x => x.id === threadId);
  if (!t) return res.status(404).json({ error: "not_found" });
  t.posts = (t.posts || []).filter(p => p.id !== postId);
  db.attachments = db.attachments.filter(a => !(a.threadId === threadId && a.postId === postId));
  t.updatedAt = nowISO();
  writeDB(db);
  res.json({ ok:true });
});

app.get(`${API}/admin/attachments`, mustAdmin, (req, res) => {
  const status = String(req.query.status || "pending");
  const db = readDB();
  const mapThreadTitle = new Map(db.threads.map((t) => [t.id, t.title]));
  const attachments = db.attachments
    .filter((a) => (status ? a.status === status : true))
    .map((a) => ({ ...a, threadTitle: mapThreadTitle.get(a.threadId) || "" }))
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
  res.json({ ok:true, attachment: att });
});

app.get(`${API}/admin/verify`, mustAdmin, (req, res) => {
  const status = String(req.query.status || "pending");
  const db = readDB();
  const requests = db.verifyRequests
    .filter(v => (status ? v.status === status : true))
    .sort((a,b)=>String(b.createdAt||"").localeCompare(String(a.createdAt||"")));
  res.json({ requests });
});

app.post(`${API}/admin/verify/review`, mustAdmin, (req, res) => {
  const requestId = String(req.body?.requestId || "");
  const action = String(req.body?.action || "");
  const note = sanitizeText(req.body?.note, 800);

  const db = readDB();
  const vr = db.verifyRequests.find(v => v.id === requestId);
  if (!vr) return res.status(404).json({ error: "not_found" });
  if (vr.status !== "pending") return res.status(400).json({ error: "already_reviewed" });
  if (action !== "approve" && action !== "reject") return res.status(400).json({ error: "bad_action" });

  vr.status = action === "approve" ? "approved" : "rejected";
  vr.note = note;
  vr.reviewedAt = nowISO();
  if (action === "approve"){
    db.verifiedUsers ||= {};
    db.verifiedUsers[vr.userId] = { verifiedAt: nowISO(), requestId: vr.id };
  }
  writeDB(db);
  res.json({ ok:true });
});

app.get("/", (req, res) => res.send("ok"));
app.listen(PORT, () => console.log(`listening :${PORT}`));
