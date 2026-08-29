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
const COLLAB_AGENTMAIL_API_KEY = process.env.COLLAB_AGENTMAIL_API_KEY;
const COLLAB_AGENTMAIL_INBOX = process.env.COLLAB_AGENTMAIL_INBOX || "siteflow.collaboration@agentmail.to";
const SITEFLOW_APP_URL = String(process.env.SITEFLOW_APP_URL || process.env.RAILWAY_PUBLIC_DOMAIN || "").trim();

if (!AGENTMAIL_API_KEY) console.warn("WARNING: AGENTMAIL_API_KEY is not set.");
if (!VERIFICATION_SECRET) console.warn("WARNING: VERIFICATION_SECRET is not set.");
if (!DATABASE_URL) console.warn("WARNING: DATABASE_URL is not set. Inbox data will use temporary memory storage until PostgreSQL is added.");
if (!COLLAB_AGENTMAIL_API_KEY) console.warn("WARNING: COLLAB_AGENTMAIL_API_KEY is not set. Collaboration invitations cannot be emailed.");

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));

// Public form submissions may come from a downloaded SiteFlow site hosted on another domain.
app.use("/api/form-submit", (req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

const verificationRequests = new Map();
const memoryWorkspaces = new Map();
const memoryMessages = [];
const memoryInvites = new Map();
const memoryMembers = new Map();
const memoryProjectStates = new Map();

const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl: /railway\.app|rlwy\.net/.test(DATABASE_URL)
        ? { rejectUnauthorized: false }
        : undefined
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

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_siteflow_messages_workspace_created
    ON siteflow_messages(workspace_id, created_at DESC)
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS siteflow_project_members (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL REFERENCES siteflow_workspaces(id) ON DELETE CASCADE,
      email TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('editor','content','viewer')),
      access_key_hash TEXT NOT NULL,
      invited_by TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(workspace_id, email)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS siteflow_project_invites (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL REFERENCES siteflow_workspaces(id) ON DELETE CASCADE,
      email TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('editor','content','viewer')),
      token_hash TEXT NOT NULL UNIQUE,
      invited_by TEXT NOT NULL DEFAULT '',
      expires_at TIMESTAMPTZ NOT NULL,
      accepted_at TIMESTAMPTZ,
      revoked_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_siteflow_invites_workspace_created
    ON siteflow_project_invites(workspace_id, created_at DESC)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_siteflow_members_workspace
    ON siteflow_project_members(workspace_id)
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS siteflow_project_state (
      workspace_id TEXT PRIMARY KEY REFERENCES siteflow_workspaces(id) ON DELETE CASCADE,
      state_json JSONB NOT NULL DEFAULT '{}'::jsonb,
      revision BIGINT NOT NULL DEFAULT 1,
      updated_by TEXT NOT NULL DEFAULT '',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  console.log("SiteFlow inbox + collaboration database ready.");
}

initDatabase().catch((err) => {
  console.error("Database initialization error:", err);
});

const SEND_COOLDOWN_MS = 30 * 1000;
const CODE_TTL_MS = 10 * 60 * 1000;
const MAX_ATTEMPTS = 5;

const sendLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 12,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    ok: false,
    error: "Too many verification requests. Please try again later."
  }
});

const verifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    ok: false,
    error: "Too many verification attempts. Please try again later."
  }
});

const formLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    ok: false,
    error: "Too many form submissions. Please try again later."
  }
});

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function cleanText(value, max = 5000) {
  return String(value || "").trim().slice(0, max);
}

function isValidEmail(email) {
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function hashCode(email, code) {
  const secret = VERIFICATION_SECRET || "development-only-secret";

  return crypto
    .createHmac("sha256", secret)
    .update(`${email}:${code}`)
    .digest("hex");
}

function hashInboxKey(value) {
  return crypto
    .createHash("sha256")
    .update(String(value || ""))
    .digest("hex");
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));

  return (
    left.length === right.length &&
    crypto.timingSafeEqual(left, right)
  );
}

function createCode() {
  return String(
    crypto.randomInt(0, 1_000_000)
  ).padStart(6, "0");
}

function createId(prefix = "msg") {
  return `${prefix}_${crypto.randomBytes(12).toString("hex")}`;
}

function verificationEmailHtml(code) {
  return `<!doctype html>
<html>
<body style="margin:0;padding:0;background:#f4f5f7;font-family:Arial,Helvetica,sans-serif;color:#17181b">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="padding:32px 16px;background:#f4f5f7">
<tr>
<td align="center">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:520px;background:#fff;border:1px solid #e5e7eb;border-radius:18px">
<tr>
<td style="padding:34px">
<div style="font-size:22px;font-weight:800;margin-bottom:24px">
SiteFlow
</div>

<h1 style="font-size:25px;line-height:1.2;margin:0 0 12px">
Verify your email
</h1>

<p style="font-size:15px;line-height:1.6;color:#60646c;margin:0 0 24px">
Enter this code in SiteFlow to finish creating your account.
</p>

<div style="font-size:34px;font-weight:800;letter-spacing:8px;text-align:center;padding:20px;border-radius:14px;background:#f5f3ff;border:1px solid #e5e0ff;margin-bottom:22px">
${code}
</div>

<p style="font-size:13px;line-height:1.6;color:#767b84;margin:0">
This code expires in 10 minutes.
If you didn't request it, you can ignore this email.
</p>
</td>
</tr>
</table>
</td>
</tr>
</table>
</body>
</html>`;
}

function verificationEmailText(code) {
  return [
    "SiteFlow",
    "",
    "Verify your email",
    "",
    `Your verification code is: ${code}`,
    "",
    "This code expires in 10 minutes.",
    "If you didn't request it, you can ignore this email."
  ].join("\n");
}

async function sendWithAgentMail(to, code) {
  if (!AGENTMAIL_API_KEY) {
    throw new Error("AgentMail is not configured.");
  }

  const inboxId = encodeURIComponent(AGENTMAIL_INBOX);

  const response = await fetch(
    `https://api.agentmail.to/v0/inboxes/${inboxId}/messages/send`,
    {
      method: "POST",

      headers: {
        Authorization: `Bearer ${AGENTMAIL_API_KEY}`,
        "Content-Type": "application/json"
      },

      body: JSON.stringify({
        to,
        subject: `${code} is your SiteFlow verification code`,
        text: verificationEmailText(code),
        html: verificationEmailHtml(code)
      })
    }
  );

  if (!response.ok) {
    let details = "";

    try {
      details = JSON.stringify(await response.json());
    } catch {
      details = await response.text();
    }

    console.error(
      "AgentMail error:",
      response.status,
      details
    );

    throw new Error(
      "Could not send verification email."
    );
  }

  return response.json();
}

async function getWorkspace(workspaceId) {
  if (pool) {
    const { rows } = await pool.query(
      "SELECT * FROM siteflow_workspaces WHERE id=$1",
      [workspaceId]
    );

    return rows[0] || null;
  }

  return memoryWorkspaces.get(workspaceId) || null;
}

async function requireInboxAccess(req, res, next) {
  try {
    const workspaceId = cleanText(
      req.query.workspaceId || req.body?.workspaceId,
      200
    );

    const inboxKey = cleanText(
      req.get("x-siteflow-inbox-key"),
      500
    );

    if (!workspaceId || !inboxKey) {
      return res.status(401).json({
        ok: false,
        error: "Inbox access details are missing."
      });
    }

    const workspace = await getWorkspace(workspaceId);

    if (
      !workspace ||
      !safeEqual(
        workspace.inbox_key_hash,
        hashInboxKey(inboxKey)
      )
    ) {
      return res.status(403).json({
        ok: false,
        error: "Inbox access denied."
      });
    }

    req.workspace = workspace;
    req.workspaceId = workspaceId;

    next();
  } catch (error) {
    console.error(error);

    res.status(500).json({
      ok: false,
      error: "Could not verify inbox access."
    });
  }
}

const COLLAB_INVITE_TTL_MS =
  7 * 24 * 60 * 60 * 1000;

const COLLAB_ROLES =
  new Set([
    "editor",
    "content",
    "viewer"
  ]);

const inviteLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    ok: false,
    error: "Too many collaboration requests. Please try again later."
  }
});

function hashToken(value) {
  return crypto
    .createHash("sha256")
    .update(String(value || ""))
    .digest("hex");
}

function makeSecureToken(bytes = 32) {
  return crypto
    .randomBytes(bytes)
    .toString("base64url");
}

function normalizeRole(value) {
  const role = String(value || "")
    .trim()
    .toLowerCase();

  return COLLAB_ROLES.has(role)
    ? role
    : "";
}

function appBaseUrl(req) {
  if (SITEFLOW_APP_URL) {
    if (/^https?:\/\//i.test(SITEFLOW_APP_URL)) {
      return SITEFLOW_APP_URL.replace(/\/+$/, "");
    }

    return `https://${SITEFLOW_APP_URL.replace(/\/+$/, "")}`;
  }

  return `${req.protocol}://${req.get("host")}`;
}

function collaborationEmailHtml({
  projectName,
  inviterEmail,
  role,
  inviteUrl
}) {
  const esc = (v) =>
    String(v || "").replace(
      /[&<>"']/g,
      (ch) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;"
        })[ch]
    );

  return `<!doctype html>
<html>
<body style="margin:0;padding:0;background:#f5f6f8;font-family:Arial,Helvetica,sans-serif;color:#17181b">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="padding:34px 16px">
<tr>
<td align="center">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:560px;background:#fff;border:1px solid #e7e9ee;border-radius:20px">
<tr>
<td style="padding:36px">

<div style="font-size:22px;font-weight:800;margin-bottom:26px">
SiteFlow Collaboration
</div>

<h1 style="font-size:25px;line-height:1.25;margin:0 0 12px">
You’ve been invited to collaborate
</h1>

<p style="font-size:15px;line-height:1.65;color:#60646c;margin:0 0 20px">
${esc(inviterEmail)} invited you to work on
<strong>${esc(projectName)}</strong>
as
<strong>${esc(role)}</strong>.
</p>

<a
href="${esc(inviteUrl)}"
style="display:inline-block;background:#655df6;color:#fff;text-decoration:none;font-weight:700;padding:13px 18px;border-radius:11px"
>
Accept invitation
</a>

<p style="font-size:13px;line-height:1.6;color:#777c85;margin:24px 0 0">
This invitation expires in 7 days.
If you weren’t expecting it, you can ignore this email.
</p>

</td>
</tr>
</table>
</td>
</tr>
</table>
</body>
</html>`;
}

function collaborationEmailText({
  projectName,
  inviterEmail,
  role,
  inviteUrl
}) {
  return [
    "SiteFlow Collaboration",
    "",
    "You've been invited to collaborate.",
    "",
    `${inviterEmail} invited you to work on ${projectName} as ${role}.`,
    "",
    `Accept invitation: ${inviteUrl}`,
    "",
    "This invitation expires in 7 days."
  ].join("\n");
}

async function sendCollaborationInvite(
  to,
  payload
) {
  if (!COLLAB_AGENTMAIL_API_KEY) {
    throw new Error(
      "Collaboration AgentMail is not configured."
    );
  }

  const inboxId = encodeURIComponent(
    COLLAB_AGENTMAIL_INBOX
  );

  const response = await fetch(
    `https://api.agentmail.to/v0/inboxes/${inboxId}/messages/send`,
    {
      method: "POST",

      headers: {
        Authorization: `Bearer ${COLLAB_AGENTMAIL_API_KEY}`,
        "Content-Type": "application/json"
      },

      body: JSON.stringify({
        to,
        subject: `You're invited to collaborate on ${payload.projectName} in SiteFlow`,
        text: collaborationEmailText(payload),
        html: collaborationEmailHtml(payload)
      })
    }
  );

  if (!response.ok) {
    let details = "";

    try {
      details =
        JSON.stringify(
          await response.json()
        );
    } catch {
      details =
        await response.text();
    }

    console.error(
      "Collaboration AgentMail error:",
      response.status,
      details
    );

    throw new Error(
      "Could not send collaboration invitation."
    );
  }

  return response.json();
}

async function requireOwner(
  req,
  res,
  next
) {
  try {
    const workspaceId =
      cleanText(
        req.query.workspaceId ||
        req.body?.workspaceId,
        200
      );

    const inboxKey =
      cleanText(
        req.get(
          "x-siteflow-inbox-key"
        ),
        500
      );

    if (
      !workspaceId ||
      !inboxKey
    ) {
      return res
        .status(401)
        .json({
          ok: false,

          error:
            "Owner access details are missing."
        });
    }

    const workspace =
      await getWorkspace(
        workspaceId
      );

    if (
      !workspace ||
      !safeEqual(
        workspace.inbox_key_hash,
        hashInboxKey(
          inboxKey
        )
      )
    ) {
      return res
        .status(403)
        .json({
          ok: false,

          error:
            "Only the project owner can do that."
        });
    }

    req.workspace =
      workspace;

    req.workspaceId =
      workspaceId;

    next();
  } catch (error) {
    console.error(
      error
    );

    res
      .status(500)
      .json({
        ok: false,

        error:
          "Could not verify project owner."
      });
  }
}

async function requireCollaborator(
  req,
  res,
  next
) {
  try {
    const workspaceId =
      cleanText(
        req.query.workspaceId ||
        req.body?.workspaceId,
        200
      );

    const email =
      normalizeEmail(
        req.get(
          "x-siteflow-collab-email"
        )
      );

    const key =
      cleanText(
        req.get(
          "x-siteflow-collab-key"
        ),
        500
      );

    if (
      !workspaceId ||
      !isValidEmail(
        email
      ) ||
      !key
    ) {
      return res
        .status(401)
        .json({
          ok: false,

          error:
            "Collaboration access details are missing."
        });
    }

    let member =
      null;

    if (pool) {
      const {
        rows
      } =
        await pool.query(
          `
            SELECT *
            FROM siteflow_project_members
            WHERE workspace_id=$1
              AND email=$2
          `,
          [
            workspaceId,
            email
          ]
        );

      member =
        rows[0] ||
        null;
    } else {
      member =
        memoryMembers.get(
          `${workspaceId}:${email}`
        ) ||
        null;
    }

    if (
      !member ||
      !safeEqual(
        member.access_key_hash,
        hashToken(
          key
        )
      )
    ) {
      return res
        .status(403)
        .json({
          ok: false,

          error:
            "Collaboration access denied."
        });
    }

    req.workspaceId =
      workspaceId;

    req.member =
      member;

    next();
  } catch (error) {
    console.error(
      error
    );

    res
      .status(500)
      .json({
        ok: false,

        error:
          "Could not verify collaborator access."
      });
  }
}

async function resolveProjectAccess(
  req,
  res,
  next
) {
  try {
    const workspaceId =
      cleanText(
        req.query.workspaceId ||
        req.body?.workspaceId,
        200
      );

    if (
      !workspaceId
    ) {
      return res
        .status(400)
        .json({
          ok: false,

          error:
            "workspaceId is required."
        });
    }

    const ownerKey =
      cleanText(
        req.get(
          "x-siteflow-inbox-key"
        ),
        500
      );

    if (
      ownerKey
    ) {
      const workspace =
        await getWorkspace(
          workspaceId
        );

      if (
        workspace &&
        safeEqual(
          workspace.inbox_key_hash,
          hashInboxKey(
            ownerKey
          )
        )
      ) {
        req.workspaceId =
          workspaceId;

        req.projectAccess =
          {
            type:
              "owner",

            email:
              workspace.owner_email,

            role:
              "owner",

            canWrite:
              true
          };

        return next();
      }
    }

    const email =
      normalizeEmail(
        req.get(
          "x-siteflow-collab-email"
        )
      );

    const key =
      cleanText(
        req.get(
          "x-siteflow-collab-key"
        ),
        500
      );

    if (
      !isValidEmail(
        email
      ) ||
      !key
    ) {
      return res
        .status(401)
        .json({
          ok: false,

          error:
            "Project access details are missing."
        });
    }

    let member =
      null;

    if (pool) {
      const {
        rows
      } =
        await pool.query(
          `
            SELECT *
            FROM siteflow_project_members
            WHERE workspace_id=$1
              AND email=$2
          `,
          [
            workspaceId,
            email
          ]
        );

      member =
        rows[0] ||
        null;
    } else {
      member =
        memoryMembers.get(
          `${workspaceId}:${email}`
        ) ||
        null;
    }

    if (
      !member ||
      !safeEqual(
        member.access_key_hash,
        hashToken(
          key
        )
      )
    ) {
      return res
        .status(403)
        .json({
          ok: false,

          error:
            "Project access denied."
        });
    }

    req.workspaceId =
      workspaceId;

    req.projectAccess =
      {
        type:
          "collaborator",

        email,

        role:
          member.role,

        canWrite:
          member.role !==
          "viewer"
      };

    next();
  } catch (error) {
    console.error(
      error
    );

    res
      .status(500)
      .json({
        ok: false,

        error:
          "Could not verify project access."
      });
  }
}

app.get(
  "/api/project-state",
  resolveProjectAccess,
  async (
    req,
    res
  ) => {
    try {
      let state =
        null;

      let revision =
        0;

      let updatedAt =
        null;

      let updatedBy =
        "";

      if (pool) {
        const {
          rows
        } =
          await pool.query(
            `
              SELECT
                state_json,
                revision,
                updated_by,
                updated_at

              FROM siteflow_project_state
              WHERE workspace_id=$1
            `,
            [
              req.workspaceId
            ]
          );

        if (
          rows[0]
        ) {
          state =
            rows[0]
              .state_json;

          revision =
            Number(
              rows[0]
                .revision
            ) ||
            0;

          updatedAt =
            rows[0]
              .updated_at;

          updatedBy =
            rows[0]
              .updated_by ||
            "";
        }
      } else {
        const row =
          memoryProjectStates.get(
            req.workspaceId
          );

        if (
          row
        ) {
          ({
            state,
            revision,
            updatedAt,
            updatedBy
          } = row);
        }
      }

      res.json({
        ok: true,

        state,

        revision,

        updatedAt,

        updatedBy,

        access:
          req.projectAccess
      });
    } catch (error) {
      console.error(
        error
      );

      res
        .status(500)
        .json({
          ok: false,

          error:
            "Could not load the shared project."
        });
    }
  }
);

app.put(
  "/api/project-state",
  resolveProjectAccess,
  async (
    req,
    res
  ) => {
    try {
      if (
        !req.projectAccess
          .canWrite
      ) {
        return res
          .status(403)
          .json({
            ok: false,

            error:
              "Viewer access is read-only."
          });
      }

      const state =
        req.body?.state;

      if (
        !state ||
        typeof state !==
          "object" ||
        !Array.isArray(
          state.pages
        )
      ) {
        return res
          .status(400)
          .json({
            ok: false,

            error:
              "Project state is invalid."
          });
      }

      const payload =
        JSON.stringify(
          state
        );

      if (
        Buffer.byteLength(
          payload,
          "utf8"
        ) >
        2_500_000
      ) {
        return res
          .status(413)
          .json({
            ok: false,

            error:
              "Project is too large to sync."
          });
      }

      const expectedRevision =
        Number(
          req.body?.revision ||
          0
        );

      let revision;

      let updatedAt =
        new Date()
          .toISOString();

      if (pool) {
        const client =
          await pool.connect();

        try {
          await client.query(
            "BEGIN"
          );

          const current =
            await client.query(
              `
                SELECT revision
                FROM siteflow_project_state
                WHERE workspace_id=$1
                FOR UPDATE
              `,
              [
                req.workspaceId
              ]
            );

          const currentRevision =
            current.rows[0]
              ? Number(
                  current
                    .rows[0]
                    .revision
                )
              : 0;

          if (
            expectedRevision &&
            currentRevision &&
            expectedRevision !==
              currentRevision
          ) {
            await client.query(
              "ROLLBACK"
            );

            return res
              .status(409)
              .json({
                ok: false,

                error:
                  "This project changed somewhere else.",

                revision:
                  currentRevision
              });
          }

          revision =
            currentRevision +
            1;

          const result =
            await client.query(
              `
                INSERT INTO
                  siteflow_project_state(
                    workspace_id,
                    state_json,
                    revision,
                    updated_by,
                    updated_at
                  )

                VALUES(
                  $1,
                  $2::jsonb,
                  $3,
                  $4,
                  NOW()
                )

                ON CONFLICT(workspace_id)

                DO UPDATE SET
                  state_json =
                    EXCLUDED.state_json,

                  revision =
                    EXCLUDED.revision,

                  updated_by =
                    EXCLUDED.updated_by,

                  updated_at =
                    NOW()

                RETURNING updated_at
              `,
              [
                req.workspaceId,

                payload,

                revision,

                req.projectAccess
                  .email
              ]
            );

          updatedAt =
            result.rows[0]
              ?.updated_at ||
            updatedAt;

          await client.query(
            "COMMIT"
          );
        } catch (error) {
          try {
            await client.query(
              "ROLLBACK"
            );
          } catch {}

          throw error;
        } finally {
          client.release();
        }
      } else {
        const current =
          memoryProjectStates.get(
            req.workspaceId
          );

        const currentRevision =
          current?.revision ||
          0;

        if (
          expectedRevision &&
          currentRevision &&
          expectedRevision !==
            currentRevision
        ) {
          return res
            .status(409)
            .json({
              ok: false,

              error:
                "This project changed somewhere else.",

              revision:
                currentRevision
            });
        }

        revision =
          currentRevision +
          1;

        memoryProjectStates.set(
          req.workspaceId,
          {
            state,

            revision,

            updatedAt,

            updatedBy:
              req.projectAccess
                .email
          }
        );
      }

      res.json({
        ok: true,

        revision,

        updatedAt,

        updatedBy:
          req.projectAccess
            .email
      });
    } catch (error) {
      console.error(
        error
      );

      res
        .status(500)
        .json({
          ok: false,

          error:
            "Could not save the shared project."
        });
    }
  }
);

app.get(
  "/api/health",
  (
    req,
    res
  ) => {
    res.json({
      ok: true,

      service:
        "siteflow",

      agentmailConfigured:
        Boolean(
          AGENTMAIL_API_KEY
        ),

      inbox:
        AGENTMAIL_INBOX,

      databaseConfigured:
        Boolean(
          pool
        ),

      collaborationMailConfigured:
        Boolean(
          COLLAB_AGENTMAIL_API_KEY
        ),

      collaborationInbox:
        COLLAB_AGENTMAIL_INBOX
    });
  }
);

app.post(
  "/api/send-verification",
  sendLimiter,
  async (
    req,
    res
  ) => {
    const email =
      normalizeEmail(
        req.body?.email
      );

    if (
      !isValidEmail(
        email
      )
    ) {
      return res
        .status(400)
        .json({
          ok: false,

          error:
            "Enter a valid email address."
        });
    }

    const existing =
      verificationRequests.get(
        email
      );

    const now =
      Date.now();

    if (
      existing &&
      now -
        existing.lastSentAt <
        SEND_COOLDOWN_MS
    ) {
      const retryAfter =
        Math.ceil(
          (
            SEND_COOLDOWN_MS -
            (
              now -
              existing.lastSentAt
            )
          ) /
          1000
        );

      return res
        .status(429)
        .json({
          ok: false,

          error:
            `Please wait ${retryAfter} seconds before requesting another code.`,

          retryAfter
        });
    }

    const code =
      createCode();

    verificationRequests.set(
      email,
      {
        codeHash:
          hashCode(
            email,
            code
          ),

        expiresAt:
          now +
          CODE_TTL_MS,

        lastSentAt:
          now,

        attempts:
          0
      }
    );

    try {
      await sendWithAgentMail(
        email,
        code
      );

      return res.json({
        ok: true,

        message:
          "Verification code sent.",

        expiresIn:
          CODE_TTL_MS /
          1000,

        resendAfter:
          SEND_COOLDOWN_MS /
          1000
      });
    } catch (error) {
      verificationRequests.delete(
        email
      );

      console.error(
        error
      );

      return res
        .status(502)
        .json({
          ok: false,

          error:
            "We couldn't send the verification email. Please try again."
        });
    }
  }
);

app.post(
  "/api/verify-code",
  verifyLimiter,
  (
    req,
    res
  ) => {
    const email =
      normalizeEmail(
        req.body?.email
      );

    const code =
      String(
        req.body?.code ||
        ""
      ).replace(
        /\D/g,
        ""
      );

    if (
      !isValidEmail(
        email
      ) ||
      !/^\d{6}$/.test(
        code
      )
    ) {
      return res
        .status(400)
        .json({
          ok: false,

          error:
            "Enter your email and a 6-digit verification code."
        });
    }

    const record =
      verificationRequests.get(
        email
      );

    if (
      !record
    ) {
      return res
        .status(400)
        .json({
          ok: false,

          error:
            "No active verification code was found. Request a new one."
        });
    }

    if (
      Date.now() >
      record.expiresAt
    ) {
      verificationRequests.delete(
        email
      );

      return res
        .status(400)
        .json({
          ok: false,

          error:
            "That code has expired. Request a new one."
        });
    }

    record.attempts +=
      1;

    if (
      record.attempts >
      MAX_ATTEMPTS
    ) {
      verificationRequests.delete(
        email
      );

      return res
        .status(429)
        .json({
          ok: false,

          error:
            "Too many incorrect attempts. Request a new code."
        });
    }

    if (
      !safeEqual(
        record.codeHash,
        hashCode(
          email,
          code
        )
      )
    ) {
      return res
        .status(400)
        .json({
          ok: false,

          error:
            "That verification code is incorrect.",

          attemptsRemaining:
            Math.max(
              0,
              MAX_ATTEMPTS -
              record.attempts
            )
        });
    }

    verificationRequests.delete(
      email
    );

    return res.json({
      ok: true,

      verified:
        true,

      email
    });
  }
);

app.post(
  "/api/workspaces/register",
  async (
    req,
    res
  ) => {
    try {
      const workspaceId =
        cleanText(
          req.body
            ?.workspaceId,
          200
        );

      const inboxKey =
        cleanText(
          req.body
            ?.inboxKey,
          500
        );

      const ownerEmail =
        normalizeEmail(
          req.body
            ?.ownerEmail
        );

      const projectName =
        cleanText(
          req.body
            ?.projectName ||
          "SiteFlow Project",
          200
        );

      if (
        !workspaceId ||
        workspaceId.length <
          12 ||
        !inboxKey ||
        inboxKey.length <
          20 ||
        !isValidEmail(
          ownerEmail
        )
      ) {
        return res
          .status(400)
          .json({
            ok: false,

            error:
              "Invalid workspace registration."
          });
      }

      const hash =
        hashInboxKey(
          inboxKey
        );

      const existing =
        await getWorkspace(
          workspaceId
        );

      if (
        existing &&
        !safeEqual(
          existing.inbox_key_hash,
          hash
        )
      ) {
        return res
          .status(409)
          .json({
            ok: false,

            error:
              "This workspace is already registered with a different inbox key."
          });
      }

      if (pool) {
        await pool.query(
          `
            INSERT INTO
              siteflow_workspaces(
                id,
                inbox_key_hash,
                owner_email,
                project_name
              )

            VALUES(
              $1,
              $2,
              $3,
              $4
            )

            ON CONFLICT(id)

            DO UPDATE SET
              owner_email =
                EXCLUDED.owner_email,

              project_name =
                EXCLUDED.project_name,

              updated_at =
                NOW()
          `,
          [
            workspaceId,

            hash,

            ownerEmail,

            projectName
          ]
        );
      } else {
        memoryWorkspaces.set(
          workspaceId,
          {
            id:
              workspaceId,

            inbox_key_hash:
              hash,

            owner_email:
              ownerEmail,

            project_name:
              projectName
          }
        );
      }

      res.json({
        ok: true,

        workspaceId,

        persistent:
          Boolean(
            pool
          )
      });
    } catch (error) {
      console.error(
        error
      );

      res
        .status(500)
        .json({
          ok: false,

          error:
            "Could not register the SiteFlow inbox."
        });
    }
  }
);

app.post(
  "/api/form-submit",
  formLimiter,
  async (
    req,
    res
  ) => {
    try {
      const workspaceId =
        cleanText(
          req.body
            ?.workspaceId,
          200
        );

      const workspace =
        await getWorkspace(
          workspaceId
        );

      if (
        !workspace
      ) {
        return res
          .status(404)
          .json({
            ok: false,

            error:
              "This SiteFlow inbox is not connected yet."
          });
      }

      const senderName =
        cleanText(
          req.body?.name,
          200
        );

      const senderEmail =
        normalizeEmail(
          req.body?.email
        );

      const subject =
        cleanText(
          req.body
            ?.subject ||
          "New form submission",
          300
        );

      const message =
        cleanText(
          req.body?.message,
          10000
        );

      const pageName =
        cleanText(
          req.body?.pageName,
          200
        );

      const formName =
        cleanText(
          req.body
            ?.formName ||
          "Contact form",
          200
        );

      if (
        !senderName
      ) {
        return res
          .status(400)
          .json({
            ok: false,

            error:
              "Please enter your name."
          });
      }

      if (
        !isValidEmail(
          senderEmail
        )
      ) {
        return res
          .status(400)
          .json({
            ok: false,

            error:
              "Please enter a valid email address."
          });
      }

      if (
        !message
      ) {
        return res
          .status(400)
          .json({
            ok: false,

            error:
              "Please enter a message."
          });
      }

      const id =
        createId(
          "msg"
        );

      const createdAt =
        new Date()
          .toISOString();

      if (pool) {
        await pool.query(
          `
            INSERT INTO
              siteflow_messages(
                id,
                workspace_id,
                sender_name,
                sender_email,
                subject,
                message,
                page_name,
                form_name
              )

            VALUES(
              $1,
              $2,
              $3,
              $4,
              $5,
              $6,
              $7,
              $8
            )
          `,
          [
            id,

            workspaceId,

            senderName,

            senderEmail,

            subject,

            message,

            pageName,

            formName
          ]
        );
      } else {
        memoryMessages.unshift(
          {
            id,

            workspace_id:
              workspaceId,

            sender_name:
              senderName,

            sender_email:
              senderEmail,

            subject,

            message,

            page_name:
              pageName,

            form_name:
              formName,

            is_read:
              false,

            archived:
              false,

            created_at:
              createdAt
          }
        );
      }

      res.json({
        ok: true,

        message:
          "Message sent."
      });
    } catch (error) {
      console.error(
        error
      );

      res
        .status(500)
        .json({
          ok: false,

          error:
            "Could not send your message."
        });
    }
  }
);

app.get(
  "/api/inbox",
  requireInboxAccess,
  async (
    req,
    res
  ) => {
    try {
      const includeArchived =
        String(
          req.query
            .archived ||
          "false"
        ) ===
        "true";

      let messages;

      if (pool) {
        const {
          rows
        } =
          await pool.query(
            `
              SELECT
                id,
                sender_name,
                sender_email,
                subject,
                message,
                page_name,
                form_name,
                is_read,
                archived,
                created_at

              FROM
                siteflow_messages

              WHERE
                workspace_id=$1
                AND archived=$2

              ORDER BY
                created_at DESC

              LIMIT 500
            `,
            [
              req.workspaceId,

              includeArchived
            ]
          );

        messages =
          rows;
      } else {
        messages =
          memoryMessages
            .filter(
              (
                message
              ) =>
                message.workspace_id ===
                  req.workspaceId &&
                message.archived ===
                  includeArchived
            )
            .slice(
              0,
              500
            );
      }

      res.json({
        ok: true,

        messages,

        persistent:
          Boolean(
            pool
          )
      });
    } catch (error) {
      console.error(
        error
      );

      res
        .status(500)
        .json({
          ok: false,

          error:
            "Could not load inbox messages."
        });
    }
  }
);

app.get(
  "/api/inbox/count",
  requireInboxAccess,
  async (
    req,
    res
  ) => {
    try {
      let unread =
        0;

      if (pool) {
        const {
          rows
        } =
          await pool.query(
            `
              SELECT
                COUNT(*)::int
                AS count

              FROM
                siteflow_messages

              WHERE
                workspace_id=$1
                AND is_read=FALSE
                AND archived=FALSE
            `,
            [
              req.workspaceId
            ]
          );

        unread =
          rows[0]?.count ||
          0;
      } else {
        unread =
          memoryMessages.filter(
            (
              message
            ) =>
              message.workspace_id ===
                req.workspaceId &&
              !message.is_read &&
              !message.archived
          ).length;
      }

      res.json({
        ok: true,

        unread
      });
    } catch (error) {
      console.error(
        error
      );

      res
        .status(500)
        .json({
          ok: false,

          error:
            "Could not load unread count."
        });
    }
  }
);

app.patch(
  "/api/inbox/:id",
  requireInboxAccess,
  async (
    req,
    res
  ) => {
    try {
      const id =
        cleanText(
          req.params.id,
          200
        );

      const updates =
        {};

      if (
        typeof req.body
          ?.read ===
        "boolean"
      ) {
        updates.is_read =
          req.body.read;
      }

      if (
        typeof req.body
          ?.archived ===
        "boolean"
      ) {
        updates.archived =
          req.body.archived;
      }

      if (
        !Object.keys(
          updates
        ).length
      ) {
        return res
          .status(400)
          .json({
            ok: false,

            error:
              "No message changes supplied."
          });
      }

      if (pool) {
        const sets =
          [];

        const values =
          [
            req.workspaceId,
            id
          ];

        let n =
          3;

        for (
          const [
            key,
            value
          ] of Object.entries(
            updates
          )
        ) {
          sets.push(
            `${key}=$${n++}`
          );

          values.push(
            value
          );
        }

        const result =
          await pool.query(
            `
              UPDATE
                siteflow_messages

              SET
                ${sets.join(
                  ","
                )}

              WHERE
                workspace_id=$1
                AND id=$2
            `,
            values
          );

        if (
          !result.rowCount
        ) {
          return res
            .status(404)
            .json({
              ok: false,

              error:
                "Message not found."
            });
        }
      } else {
        const message =
          memoryMessages.find(
            (
              message
            ) =>
              message.workspace_id ===
                req.workspaceId &&
              message.id ===
                id
          );

        if (
          !message
        ) {
          return res
            .status(404)
            .json({
              ok: false,

              error:
                "Message not found."
            });
        }

        Object.assign(
          message,
          updates
        );
      }

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(
        error
      );

      res
        .status(500)
        .json({
          ok: false,

          error:
            "Could not update the message."
        });
    }
  }
);

app.delete(
  "/api/inbox/:id",
  requireInboxAccess,
  async (
    req,
    res
  ) => {
    try {
      const id =
        cleanText(
          req.params.id,
          200
        );

      if (pool) {
        const result =
          await pool.query(
            `
              DELETE FROM
                siteflow_messages

              WHERE
                workspace_id=$1
                AND id=$2
            `,
            [
              req.workspaceId,
              id
            ]
          );

        if (
          !result.rowCount
        ) {
          return res
            .status(404)
            .json({
              ok: false,

              error:
                "Message not found."
            });
        }
      } else {
        const index =
          memoryMessages
            .findIndex(
              (
                message
              ) =>
                message.workspace_id ===
                  req.workspaceId &&
                message.id ===
                  id
            );

        if (
          index <
          0
        ) {
          return res
            .status(404)
            .json({
              ok: false,

              error:
                "Message not found."
            });
        }

        memoryMessages.splice(
          index,
          1
        );
      }

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(
        error
      );

      res
        .status(500)
        .json({
          ok: false,

          error:
            "Could not delete the message."
        });
    }
  }
);

app.post(
  "/api/collaboration/invites",
  inviteLimiter,
  requireOwner,
  async (
    req,
    res
  ) => {
    try {
      const email =
        normalizeEmail(
          req.body?.email
        );

      const role =
        normalizeRole(
          req.body?.role
        );

      if (
        !isValidEmail(
          email
        )
      ) {
        return res
          .status(400)
          .json({
            ok: false,

            error:
              "Enter a valid collaborator email."
          });
      }

      if (
        !role
      ) {
        return res
          .status(400)
          .json({
            ok: false,

            error:
              "Choose editor, content, or viewer access."
          });
      }

      if (
        email ===
        normalizeEmail(
          req.workspace
            .owner_email
        )
      ) {
        return res
          .status(400)
          .json({
            ok: false,

            error:
              "The project owner is already a member."
          });
      }

      if (pool) {
        const memberCheck =
          await pool.query(
            `
              SELECT 1
              FROM siteflow_project_members
              WHERE workspace_id=$1
                AND email=$2
            `,
            [
              req.workspaceId,
              email
            ]
          );

        if (
          memberCheck
            .rowCount
        ) {
          return res
            .status(409)
            .json({
              ok: false,

              error:
                "That person is already a collaborator."
            });
        }

        await pool.query(
          `
            UPDATE
              siteflow_project_invites

            SET
              revoked_at=NOW()

            WHERE
              workspace_id=$1
              AND email=$2
              AND accepted_at IS NULL
              AND revoked_at IS NULL
          `,
          [
            req.workspaceId,
            email
          ]
        );
      } else if (
        memoryMembers.has(
          `${req.workspaceId}:${email}`
        )
      ) {
        return res
          .status(409)
          .json({
            ok: false,

            error:
              "That person is already a collaborator."
          });
      } else {
        for (
          const invite of
          memoryInvites.values()
        ) {
          if (
            invite.workspace_id ===
              req.workspaceId &&
            invite.email ===
              email &&
            !invite.accepted_at
          ) {
            invite.revoked_at =
              new Date()
                .toISOString();
          }
        }
      }

      const rawToken =
        makeSecureToken();

      const tokenHash =
        hashToken(
          rawToken
        );

      const id =
        createId(
          "invite"
        );

      const expiresAt =
        new Date(
          Date.now() +
          COLLAB_INVITE_TTL_MS
        ).toISOString();

      const invitedBy =
        normalizeEmail(
          req.workspace
            .owner_email
        );

      if (pool) {
        await pool.query(
          `
            INSERT INTO
              siteflow_project_invites(
                id,
                workspace_id,
                email,
                role,
                token_hash,
                invited_by,
                expires_at
              )

            VALUES(
              $1,
              $2,
              $3,
              $4,
              $5,
              $6,
              $7
            )
          `,
          [
            id,
            req.workspaceId,
            email,
            role,
            tokenHash,
            invitedBy,
            expiresAt
          ]
        );
      } else {
        memoryInvites.set(
          id,
          {
            id,

            workspace_id:
              req.workspaceId,

            email,

            role,

            token_hash:
              tokenHash,

            invited_by:
              invitedBy,

            expires_at:
              expiresAt,

            accepted_at:
              null,

            revoked_at:
              null,

            created_at:
              new Date()
                .toISOString()
          }
        );
      }

      const inviteUrl =
        `${appBaseUrl(
          req
        )}/?siteflowInvite=${encodeURIComponent(
          rawToken
        )}`;

      try {
        await sendCollaborationInvite(
          email,
          {
            projectName:
              req.workspace
                .project_name,

            inviterEmail:
              invitedBy,

            role,

            inviteUrl
          }
        );
      } catch (mailError) {
        if (pool) {
          await pool.query(
            `
              DELETE FROM
                siteflow_project_invites

              WHERE id=$1
            `,
            [
              id
            ]
          );
        } else {
          memoryInvites.delete(
            id
          );
        }

        throw mailError;
      }

      res.json({
        ok: true,

        invite: {
          id,

          email,

          role,

          status:
            "pending",

          expiresAt
        }
      });
    } catch (error) {
      console.error(
        error
      );

      res
        .status(502)
        .json({
          ok: false,

          error:
            error.message ===
            "Could not send collaboration invitation."
              ? error.message
              : "Could not create collaboration invitation."
        });
    }
  }
);

app.get(
  "/api/collaboration",
  requireOwner,
  async (
    req,
    res
  ) => {
    try {
      let members =
        [];

      let invites =
        [];

      if (pool) {
        const membersResult =
          await pool.query(
            `
              SELECT
                id,
                email,
                role,
                invited_by,
                created_at,
                updated_at

              FROM
                siteflow_project_members

              WHERE
                workspace_id=$1

              ORDER BY
                created_at ASC
            `,
            [
              req.workspaceId
            ]
          );

        const invitesResult =
          await pool.query(
            `
              SELECT
                id,
                email,
                role,
                invited_by,
                expires_at,
                accepted_at,
                revoked_at,
                created_at

              FROM
                siteflow_project_invites

              WHERE
                workspace_id=$1

              ORDER BY
                created_at DESC

              LIMIT 100
            `,
            [
              req.workspaceId
            ]
          );

        members =
          membersResult.rows;

        invites =
          invitesResult.rows.map(
            (
              invite
            ) => ({
              ...invite,

              status:
                invite.accepted_at
                  ? "accepted"
                  : invite.revoked_at
                    ? "revoked"
                    : new Date(
                        invite.expires_at
                      ).getTime() <
                      Date.now()
                      ? "expired"
                      : "pending"
            })
          );
      } else {
        members =
          [
            ...memoryMembers.values()
          ]
            .filter(
              (
                member
              ) =>
                member.workspace_id ===
                req.workspaceId
            )
            .map(
              ({
                access_key_hash,
                ...member
              }) =>
                member
            );

        invites =
          [
            ...memoryInvites.values()
          ]
            .filter(
              (
                invite
              ) =>
                invite.workspace_id ===
                req.workspaceId
            )
            .map(
              (
                invite
              ) => ({
                ...invite,

                token_hash:
                  undefined,

                status:
                  invite.accepted_at
                    ? "accepted"
                    : invite.revoked_at
                      ? "revoked"
                      : new Date(
                          invite.expires_at
                        ).getTime() <
                        Date.now()
                        ? "expired"
                        : "pending"
              })
            );
      }

      res.json({
        ok: true,

        owner: {
          email:
            req.workspace
              .owner_email,

          role:
            "owner"
        },

        members,

        invites
      });
    } catch (error) {
      console.error(
        error
      );

      res
        .status(500)
        .json({
          ok: false,

          error:
            "Could not load collaboration members."
        });
    }
  }
);

app.get(
  "/api/collaboration/invites/preview",
  inviteLimiter,
  async (
    req,
    res
  ) => {
    try {
      const token =
        cleanText(
          req.query.token,
          1000
        );

      if (
        !token
      ) {
        return res
          .status(400)
          .json({
            ok: false,

            error:
              "Invitation token is missing."
          });
      }

      const tokenHash =
        hashToken(
          token
        );

      let invite =
        null;

      let projectName =
        "SiteFlow Project";

      if (pool) {
        const {
          rows
        } =
          await pool.query(
            `
              SELECT
                i.*,
                w.project_name

              FROM
                siteflow_project_invites i

              JOIN
                siteflow_workspaces w

              ON
                w.id =
                i.workspace_id

              WHERE
                i.token_hash=$1
            `,
            [
              tokenHash
            ]
          );

        invite =
          rows[0] ||
          null;

        projectName =
          invite?.project_name ||
          projectName;
      } else {
        invite =
          [
            ...memoryInvites.values()
          ].find(
            (
              invite
            ) =>
              safeEqual(
                invite.token_hash,
                tokenHash
              )
          ) ||
          null;

        if (
          invite
        ) {
          projectName =
            (
              await getWorkspace(
                invite.workspace_id
              )
            )
              ?.project_name ||
            projectName;
        }
      }

      if (
        !invite
      ) {
        return res
          .status(404)
          .json({
            ok: false,

            error:
              "Invitation not found."
          });
      }

      if (
        invite.revoked_at
      ) {
        return res
          .status(410)
          .json({
            ok: false,

            error:
              "This invitation was revoked."
          });
      }

      if (
        invite.accepted_at
      ) {
        return res
          .status(410)
          .json({
            ok: false,

            error:
              "This invitation has already been accepted."
          });
      }

      if (
        new Date(
          invite.expires_at
        ).getTime() <
        Date.now()
      ) {
        return res
          .status(410)
          .json({
            ok: false,

            error:
              "This invitation has expired."
          });
      }

      res.json({
        ok: true,

        invite: {
          email:
            invite.email,

          role:
            invite.role,

          projectName,

          invitedBy:
            invite.invited_by,

          expiresAt:
            invite.expires_at
        }
      });
    } catch (error) {
      console.error(
        error
      );

      res
        .status(500)
        .json({
          ok: false,

          error:
            "Could not load invitation."
        });
    }
  }
);

app.post(
  "/api/collaboration/invites/accept",
  inviteLimiter,
  async (
    req,
    res
  ) => {
    try {
      const token =
        cleanText(
          req.body?.token,
          1000
        );

      const email =
        normalizeEmail(
          req.body?.email
        );

      if (
        !token ||
        !isValidEmail(
          email
        )
      ) {
        return res
          .status(400)
          .json({
            ok: false,

            error:
              "Invitation and email are required."
          });
      }

      const tokenHash =
        hashToken(
          token
        );

      let invite =
        null;

      if (pool) {
        const {
          rows
        } =
          await pool.query(
            `
              SELECT *
              FROM siteflow_project_invites
              WHERE token_hash=$1
            `,
            [
              tokenHash
            ]
          );

        invite =
          rows[0] ||
          null;
      } else {
        invite =
          [
            ...memoryInvites.values()
          ].find(
            (
              invite
            ) =>
              safeEqual(
                invite.token_hash,
                tokenHash
              )
          ) ||
          null;
      }

      if (
        !invite ||
        invite.email !==
          email
      ) {
        return res
          .status(403)
          .json({
            ok: false,

            error:
              "This invitation does not match that email."
          });
      }

      if (
        invite.revoked_at
      ) {
        return res
          .status(410)
          .json({
            ok: false,

            error:
              "This invitation was revoked."
          });
      }

      if (
        invite.accepted_at
      ) {
        return res
          .status(410)
          .json({
            ok: false,

            error:
              "This invitation has already been accepted."
          });
      }

      if (
        new Date(
          invite.expires_at
        ).getTime() <
        Date.now()
      ) {
        return res
          .status(410)
          .json({
            ok: false,

            error:
              "This invitation has expired."
          });
      }

      const accessKey =
        makeSecureToken();

      const accessKeyHash =
        hashToken(
          accessKey
        );

      const memberId =
        createId(
          "member"
        );

      if (pool) {
        const client =
          await pool.connect();

        try {
          await client.query(
            "BEGIN"
          );

          await client.query(
            `
              INSERT INTO
                siteflow_project_members(
                  id,
                  workspace_id,
                  email,
                  role,
                  access_key_hash,
                  invited_by
                )

              VALUES(
                $1,
                $2,
                $3,
                $4,
                $5,
                $6
              )

              ON CONFLICT(
                workspace_id,
                email
              )

              DO UPDATE SET
                role =
                  EXCLUDED.role,

                access_key_hash =
                  EXCLUDED.access_key_hash,

                updated_at =
                  NOW()
            `,
            [
              memberId,

              invite.workspace_id,

              email,

              invite.role,

              accessKeyHash,

              invite.invited_by
            ]
          );

          await client.query(
            `
              UPDATE
                siteflow_project_invites

              SET
                accepted_at=NOW()

              WHERE
                id=$1
            `,
            [
              invite.id
            ]
          );

          await client.query(
            "COMMIT"
          );
        } catch (error) {
          await client.query(
            "ROLLBACK"
          );

          throw error;
        } finally {
          client.release();
        }
      } else {
        memoryMembers.set(
          `${invite.workspace_id}:${email}`,
          {
            id:
              memberId,

            workspace_id:
              invite.workspace_id,

            email,

            role:
              invite.role,

            access_key_hash:
              accessKeyHash,

            invited_by:
              invite.invited_by,

            created_at:
              new Date()
                .toISOString(),

            updated_at:
              new Date()
                .toISOString()
          }
        );

        invite.accepted_at =
          new Date()
            .toISOString();
      }

      res.json({
        ok: true,

        workspaceId:
          invite.workspace_id,

        member: {
          email,

          role:
            invite.role
        },

        collaborationKey:
          accessKey
      });
    } catch (error) {
      console.error(
        error
      );

      res
        .status(500)
        .json({
          ok: false,

          error:
            "Could not accept invitation."
        });
    }
  }
);

app.patch(
  "/api/collaboration/members/:id",
  requireOwner,
  async (
    req,
    res
  ) => {
    try {
      const id =
        cleanText(
          req.params.id,
          200
        );

      const role =
        normalizeRole(
          req.body?.role
        );

      if (
        !role
      ) {
        return res
          .status(400)
          .json({
            ok: false,

            error:
              "Choose editor, content, or viewer access."
          });
      }

      if (pool) {
        const result =
          await pool.query(
            `
              UPDATE
                siteflow_project_members

              SET
                role=$1,
                updated_at=NOW()

              WHERE
                workspace_id=$2
                AND id=$3
            `,
            [
              role,
              req.workspaceId,
              id
            ]
          );

        if (
          !result.rowCount
        ) {
          return res
            .status(404)
            .json({
              ok: false,

              error:
                "Collaborator not found."
            });
        }
      } else {
        const member =
          [
            ...memoryMembers.values()
          ].find(
            (
              member
            ) =>
              member.workspace_id ===
                req.workspaceId &&
              member.id ===
                id
          );

        if (
          !member
        ) {
          return res
            .status(404)
            .json({
              ok: false,

              error:
                "Collaborator not found."
            });
        }

        member.role =
          role;

        member.updated_at =
          new Date()
            .toISOString();
      }

      res.json({
        ok: true,

        role
      });
    } catch (error) {
      console.error(
        error
      );

      res
        .status(500)
        .json({
          ok: false,

          error:
            "Could not update collaborator."
        });
    }
  }
);

app.delete(
  "/api/collaboration/members/:id",
  requireOwner,
  async (
    req,
    res
  ) => {
    try {
      const id =
        cleanText(
          req.params.id,
          200
        );

      if (pool) {
        const result =
          await pool.query(
            `
              DELETE FROM
                siteflow_project_members

              WHERE
                workspace_id=$1
                AND id=$2
            `,
            [
              req.workspaceId,
              id
            ]
          );

        if (
          !result.rowCount
        ) {
          return res
            .status(404)
            .json({
              ok: false,

              error:
                "Collaborator not found."
            });
        }
      } else {
        const entry =
          [
            ...memoryMembers.entries()
          ].find(
            ([
              ,
              member
            ]) =>
              member.workspace_id ===
                req.workspaceId &&
              member.id ===
                id
          );

        if (
          !entry
        ) {
          return res
            .status(404)
            .json({
              ok: false,

              error:
                "Collaborator not found."
            });
        }

        memoryMembers.delete(
          entry[0]
        );
      }

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(
        error
      );

      res
        .status(500)
        .json({
          ok: false,

          error:
            "Could not remove collaborator."
        });
    }
  }
);

app.delete(
  "/api/collaboration/invites/:id",
  requireOwner,
  async (
    req,
    res
  ) => {
    try {
      const id =
        cleanText(
          req.params.id,
          200
        );

      if (pool) {
        const result =
          await pool.query(
            `
              UPDATE
                siteflow_project_invites

              SET
                revoked_at=NOW()

              WHERE
                workspace_id=$1
                AND id=$2
                AND accepted_at IS NULL
                AND revoked_at IS NULL
            `,
            [
              req.workspaceId,
              id
            ]
          );

        if (
          !result.rowCount
        ) {
          return res
            .status(404)
            .json({
              ok: false,

              error:
                "Pending invitation not found."
            });
        }
      } else {
        const invite =
          memoryInvites.get(
            id
          );

        if (
          !invite ||
          invite.workspace_id !==
            req.workspaceId ||
          invite.accepted_at ||
          invite.revoked_at
        ) {
          return res
            .status(404)
            .json({
              ok: false,

              error:
                "Pending invitation not found."
            });
        }

        invite.revoked_at =
          new Date()
            .toISOString();
      }

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(
        error
      );

      res
        .status(500)
        .json({
          ok: false,

          error:
            "Could not revoke invitation."
        });
    }
  }
);

app.get(
  "/api/collaboration/me",
  requireCollaborator,
  async (
    req,
    res
  ) => {
    res.json({
      ok: true,

      member: {
        email:
          req.member.email,

        role:
          req.member.role,

        workspaceId:
          req.workspaceId
      }
    });
  }
);

setInterval(
  () => {
    const now =
      Date.now();

    for (
      const [
        email,
        record
      ] of
      verificationRequests.entries()
    ) {
      if (
        now >
        record.expiresAt
      ) {
        verificationRequests.delete(
          email
        );
      }
    }
  },
  60 * 1000
).unref();

app.listen(
  PORT,
  () => {
    console.log(
      `SiteFlow server running on port ${PORT}`
    );
  }
);
