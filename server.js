const express = require("express");
const path = require("path");
const crypto = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
const AGENTMAIL_API_KEY = process.env.AGENTMAIL_API_KEY;
const AGENTMAIL_INBOX = process.env.AGENTMAIL_INBOX || "siteflow.verify@agentmail.to";
const VERIFICATION_SECRET = process.env.VERIFICATION_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!AGENTMAIL_API_KEY) console.warn("WARNING: AGENTMAIL_API_KEY is not set.");
if (!VERIFICATION_SECRET) console.warn("WARNING: VERIFICATION_SECRET is not set.");
if (!DATABASE_URL) console.warn("WARNING: DATABASE_URL is not set. Inbox data will use temporary memory storage until PostgreSQL is added.");

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
// Public form submissions may come from a downloaded SiteFlow site hosted on another domain.
app.use("/api/form-submit", (req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
app.use(express.static(__dirname));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

const verificationRequests = new Map();
const memoryWorkspaces = new Map();
const memoryMessages = [];

const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl: /railway\.app|rlwy\.net/.test(DATABASE_URL) ? { rejectUnauthorized: false } : undefined
    })
  : null;

async function initDatabase() {
  if (!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS siteflow_workspaces (
      id TEXT PRIMARY KEY,
      inbox_key_hash TEXT NOT NULL,
      owner_email TEXT NOT NULL,
      project_name TEXT NOT NULL DEFAULT 'SiteFlow Project',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS siteflow_messages (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL REFERENCES siteflow_workspaces(id) ON DELETE CASCADE,
      sender_name TEXT NOT NULL DEFAULT '',
      sender_email TEXT NOT NULL DEFAULT '',
      subject TEXT NOT NULL DEFAULT 'New form submission',
      message TEXT NOT NULL DEFAULT '',
      page_name TEXT NOT NULL DEFAULT '',
      form_name TEXT NOT NULL DEFAULT 'Contact form',
      is_read BOOLEAN NOT NULL DEFAULT FALSE,
      archived BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_siteflow_messages_workspace_created ON siteflow_messages(workspace_id, created_at DESC)`);
  console.log("SiteFlow inbox database ready.");
}

initDatabase().catch(err => console.error("Database initialization error:", err));

const SEND_COOLDOWN_MS = 30 * 1000;
const CODE_TTL_MS = 10 * 60 * 1000;
const MAX_ATTEMPTS = 5;

const sendLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 12,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: "Too many verification requests. Please try again later." }
});
const verifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: "Too many verification attempts. Please try again later." }
});
const formLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: "Too many form submissions. Please try again later." }
});

function normalizeEmail(value) { return String(value || "").trim().toLowerCase(); }
function cleanText(value, max = 5000) { return String(value || "").trim().slice(0, max); }
function isValidEmail(email) { return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
function hashCode(email, code) {
  const secret = VERIFICATION_SECRET || "development-only-secret";
  return crypto.createHmac("sha256", secret).update(`${email}:${code}`).digest("hex");
}
function hashInboxKey(value) { return crypto.createHash("sha256").update(String(value || "")).digest("hex"); }
function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}
function createCode() { return String(crypto.randomInt(0, 1_000_000)).padStart(6, "0"); }
function createId(prefix = "msg") { return `${prefix}_${crypto.randomBytes(12).toString("hex")}`; }

function verificationEmailHtml(code) {
  return `<!doctype html><html><body style="margin:0;padding:0;background:#f4f5f7;font-family:Arial,Helvetica,sans-serif;color:#17181b"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="padding:32px 16px;background:#f4f5f7"><tr><td align="center"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:520px;background:#fff;border:1px solid #e5e7eb;border-radius:18px"><tr><td style="padding:34px"><div style="font-size:22px;font-weight:800;margin-bottom:24px">SiteFlow</div><h1 style="font-size:25px;line-height:1.2;margin:0 0 12px">Verify your email</h1><p style="font-size:15px;line-height:1.6;color:#60646c;margin:0 0 24px">Enter this code in SiteFlow to finish creating your account.</p><div style="font-size:34px;font-weight:800;letter-spacing:8px;text-align:center;padding:20px;border-radius:14px;background:#f5f3ff;border:1px solid #e5e0ff;margin-bottom:22px">${code}</div><p style="font-size:13px;line-height:1.6;color:#767b84;margin:0">This code expires in 10 minutes. If you didn't request it, you can ignore this email.</p></td></tr></table></td></tr></table></body></html>`;
}
function verificationEmailText(code) {
  return ["SiteFlow", "", "Verify your email", "", `Your verification code is: ${code}`, "", "This code expires in 10 minutes.", "If you didn't request it, you can ignore this email."].join("\n");
}
async function sendWithAgentMail(to, code) {
  if (!AGENTMAIL_API_KEY) throw new Error("AgentMail is not configured.");
  const inboxId = encodeURIComponent(AGENTMAIL_INBOX);
  const response = await fetch(`https://api.agentmail.to/v0/inboxes/${inboxId}/messages/send`, {
    method: "POST",
    headers: { Authorization: `Bearer ${AGENTMAIL_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ to, subject: `${code} is your SiteFlow verification code`, text: verificationEmailText(code), html: verificationEmailHtml(code) })
  });
  if (!response.ok) {
    let details = "";
    try { details = JSON.stringify(await response.json()); } catch { details = await response.text(); }
    console.error("AgentMail error:", response.status, details);
    throw new Error("Could not send verification email.");
  }
  return response.json();
}

async function getWorkspace(workspaceId) {
  if (pool) {
    const { rows } = await pool.query("SELECT * FROM siteflow_workspaces WHERE id=$1", [workspaceId]);
    return rows[0] || null;
  }
  return memoryWorkspaces.get(workspaceId) || null;
}

async function requireInboxAccess(req, res, next) {
  try {
    const workspaceId = cleanText(req.query.workspaceId || req.body?.workspaceId, 200);
    const inboxKey = cleanText(req.get("x-siteflow-inbox-key"), 500);
    if (!workspaceId || !inboxKey) return res.status(401).json({ ok: false, error: "Inbox access details are missing." });
    const workspace = await getWorkspace(workspaceId);
    if (!workspace || !safeEqual(workspace.inbox_key_hash, hashInboxKey(inboxKey))) {
      return res.status(403).json({ ok: false, error: "Inbox access denied." });
    }
    req.workspace = workspace;
    req.workspaceId = workspaceId;
    next();
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, error: "Could not verify inbox access." });
  }
}

app.get("/api/health", (req, res) => res.json({
  ok: true,
  service: "siteflow",
  agentmailConfigured: Boolean(AGENTMAIL_API_KEY),
  inbox: AGENTMAIL_INBOX,
  databaseConfigured: Boolean(pool)
}));

app.post("/api/send-verification", sendLimiter, async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  if (!isValidEmail(email)) return res.status(400).json({ ok: false, error: "Enter a valid email address." });
  const existing = verificationRequests.get(email);
  const now = Date.now();
  if (existing && now - existing.lastSentAt < SEND_COOLDOWN_MS) {
    const retryAfter = Math.ceil((SEND_COOLDOWN_MS - (now - existing.lastSentAt)) / 1000);
    return res.status(429).json({ ok: false, error: `Please wait ${retryAfter} seconds before requesting another code.`, retryAfter });
  }
  const code = createCode();
  verificationRequests.set(email, { codeHash: hashCode(email, code), expiresAt: now + CODE_TTL_MS, lastSentAt: now, attempts: 0 });
  try {
    await sendWithAgentMail(email, code);
    return res.json({ ok: true, message: "Verification code sent.", expiresIn: CODE_TTL_MS / 1000, resendAfter: SEND_COOLDOWN_MS / 1000 });
  } catch (error) {
    verificationRequests.delete(email);
    console.error(error);
    return res.status(502).json({ ok: false, error: "We couldn't send the verification email. Please try again." });
  }
});

app.post("/api/verify-code", verifyLimiter, (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const code = String(req.body?.code || "").replace(/\D/g, "");
  if (!isValidEmail(email) || !/^\d{6}$/.test(code)) return res.status(400).json({ ok: false, error: "Enter your email and a 6-digit verification code." });
  const record = verificationRequests.get(email);
  if (!record) return res.status(400).json({ ok: false, error: "No active verification code was found. Request a new one." });
  if (Date.now() > record.expiresAt) { verificationRequests.delete(email); return res.status(400).json({ ok: false, error: "That code has expired. Request a new one." }); }
  record.attempts += 1;
  if (record.attempts > MAX_ATTEMPTS) { verificationRequests.delete(email); return res.status(429).json({ ok: false, error: "Too many incorrect attempts. Request a new code." }); }
  if (!safeEqual(record.codeHash, hashCode(email, code))) return res.status(400).json({ ok: false, error: "That verification code is incorrect.", attemptsRemaining: Math.max(0, MAX_ATTEMPTS - record.attempts) });
  verificationRequests.delete(email);
  return res.json({ ok: true, verified: true, email });
});

app.post("/api/workspaces/register", async (req, res) => {
  try {
    const workspaceId = cleanText(req.body?.workspaceId, 200);
    const inboxKey = cleanText(req.body?.inboxKey, 500);
    const ownerEmail = normalizeEmail(req.body?.ownerEmail);
    const projectName = cleanText(req.body?.projectName || "SiteFlow Project", 200);
    if (!workspaceId || workspaceId.length < 12 || !inboxKey || inboxKey.length < 20 || !isValidEmail(ownerEmail)) {
      return res.status(400).json({ ok: false, error: "Invalid workspace registration." });
    }
    const hash = hashInboxKey(inboxKey);
    const existing = await getWorkspace(workspaceId);
    if (existing && !safeEqual(existing.inbox_key_hash, hash)) {
      return res.status(409).json({ ok: false, error: "This workspace is already registered with a different inbox key." });
    }
    if (pool) {
      await pool.query(`
        INSERT INTO siteflow_workspaces(id,inbox_key_hash,owner_email,project_name)
        VALUES($1,$2,$3,$4)
        ON CONFLICT(id) DO UPDATE SET owner_email=EXCLUDED.owner_email, project_name=EXCLUDED.project_name, updated_at=NOW()
      `, [workspaceId, hash, ownerEmail, projectName]);
    } else {
      memoryWorkspaces.set(workspaceId, { id: workspaceId, inbox_key_hash: hash, owner_email: ownerEmail, project_name: projectName });
    }
    res.json({ ok: true, workspaceId, persistent: Boolean(pool) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, error: "Could not register the SiteFlow inbox." });
  }
});

app.post("/api/form-submit", formLimiter, async (req, res) => {
  try {
    const workspaceId = cleanText(req.body?.workspaceId, 200);
    const workspace = await getWorkspace(workspaceId);
    if (!workspace) return res.status(404).json({ ok: false, error: "This SiteFlow inbox is not connected yet." });

    const senderName = cleanText(req.body?.name, 200);
    const senderEmail = normalizeEmail(req.body?.email);
    const subject = cleanText(req.body?.subject || "New form submission", 300);
    const message = cleanText(req.body?.message, 10000);
    const pageName = cleanText(req.body?.pageName, 200);
    const formName = cleanText(req.body?.formName || "Contact form", 200);

    if (!senderName) return res.status(400).json({ ok: false, error: "Please enter your name." });
    if (!isValidEmail(senderEmail)) return res.status(400).json({ ok: false, error: "Please enter a valid email address." });
    if (!message) return res.status(400).json({ ok: false, error: "Please enter a message." });

    const id = createId("msg");
    const createdAt = new Date().toISOString();
    if (pool) {
      await pool.query(`
        INSERT INTO siteflow_messages(id,workspace_id,sender_name,sender_email,subject,message,page_name,form_name)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8)
      `, [id, workspaceId, senderName, senderEmail, subject, message, pageName, formName]);
    } else {
      memoryMessages.unshift({ id, workspace_id: workspaceId, sender_name: senderName, sender_email: senderEmail, subject, message, page_name: pageName, form_name: formName, is_read: false, archived: false, created_at: createdAt });
    }
    res.json({ ok: true, message: "Message sent." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, error: "Could not send your message." });
  }
});

app.get("/api/inbox", requireInboxAccess, async (req, res) => {
  try {
    const includeArchived = String(req.query.archived || "false") === "true";
    let messages;
    if (pool) {
      const { rows } = await pool.query(`
        SELECT id,sender_name,sender_email,subject,message,page_name,form_name,is_read,archived,created_at
        FROM siteflow_messages
        WHERE workspace_id=$1 AND archived=$2
        ORDER BY created_at DESC
        LIMIT 500
      `, [req.workspaceId, includeArchived]);
      messages = rows;
    } else {
      messages = memoryMessages.filter(m => m.workspace_id === req.workspaceId && m.archived === includeArchived).slice(0, 500);
    }
    res.json({ ok: true, messages, persistent: Boolean(pool) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, error: "Could not load inbox messages." });
  }
});

app.get("/api/inbox/count", requireInboxAccess, async (req, res) => {
  try {
    let unread = 0;
    if (pool) {
      const { rows } = await pool.query("SELECT COUNT(*)::int AS count FROM siteflow_messages WHERE workspace_id=$1 AND is_read=FALSE AND archived=FALSE", [req.workspaceId]);
      unread = rows[0]?.count || 0;
    } else {
      unread = memoryMessages.filter(m => m.workspace_id === req.workspaceId && !m.is_read && !m.archived).length;
    }
    res.json({ ok: true, unread });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, error: "Could not load unread count." });
  }
});

app.patch("/api/inbox/:id", requireInboxAccess, async (req, res) => {
  try {
    const id = cleanText(req.params.id, 200);
    const updates = {};
    if (typeof req.body?.read === "boolean") updates.is_read = req.body.read;
    if (typeof req.body?.archived === "boolean") updates.archived = req.body.archived;
    if (!Object.keys(updates).length) return res.status(400).json({ ok: false, error: "No message changes supplied." });

    if (pool) {
      const sets = [];
      const values = [req.workspaceId, id];
      let n = 3;
      for (const [key, value] of Object.entries(updates)) { sets.push(`${key}=$${n++}`); values.push(value); }
      const result = await pool.query(`UPDATE siteflow_messages SET ${sets.join(",")} WHERE workspace_id=$1 AND id=$2`, values);
      if (!result.rowCount) return res.status(404).json({ ok: false, error: "Message not found." });
    } else {
      const msg = memoryMessages.find(m => m.workspace_id === req.workspaceId && m.id === id);
      if (!msg) return res.status(404).json({ ok: false, error: "Message not found." });
      Object.assign(msg, updates);
    }
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, error: "Could not update the message." });
  }
});

app.delete("/api/inbox/:id", requireInboxAccess, async (req, res) => {
  try {
    const id = cleanText(req.params.id, 200);
    if (pool) {
      const result = await pool.query("DELETE FROM siteflow_messages WHERE workspace_id=$1 AND id=$2", [req.workspaceId, id]);
      if (!result.rowCount) return res.status(404).json({ ok: false, error: "Message not found." });
    } else {
      const idx = memoryMessages.findIndex(m => m.workspace_id === req.workspaceId && m.id === id);
      if (idx < 0) return res.status(404).json({ ok: false, error: "Message not found." });
      memoryMessages.splice(idx, 1);
    }
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, error: "Could not delete the message." });
  }
});

setInterval(() => {
  const now = Date.now();
  for (const [email, record] of verificationRequests.entries()) if (now > record.expiresAt) verificationRequests.delete(email);
}, 60 * 1000).unref();

app.listen(PORT, () => console.log(`SiteFlow server running on port ${PORT}`));
