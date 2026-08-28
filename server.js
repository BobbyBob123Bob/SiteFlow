const express = require("express");
const path = require("path");
const crypto = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

const AGENTMAIL_API_KEY = process.env.AGENTMAIL_API_KEY;
const AGENTMAIL_INBOX = process.env.AGENTMAIL_INBOX || "siteflow.dont.reply@agentmail.to";
const VERIFICATION_SECRET = process.env.VERIFICATION_SECRET;

if (!AGENTMAIL_API_KEY) {
  console.warn("WARNING: AGENTMAIL_API_KEY is not set.");
}
if (!VERIFICATION_SECRET) {
  console.warn("WARNING: VERIFICATION_SECRET is not set.");
}

app.use(helmet({
  contentSecurityPolicy: false
}));
app.use(express.json({ limit: "20kb" }));

// Serve your existing SiteFlow index.html from /public
app.use(express.static(path.join(__dirname, "public")));

const verificationRequests = new Map();

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

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function isValidEmail(email) {
  if (email.length > 254) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function hashCode(email, code) {
  const secret = VERIFICATION_SECRET || "development-only-secret";
  return crypto
    .createHmac("sha256", secret)
    .update(`${email}:${code}`)
    .digest("hex");
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function createCode() {
  return String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
}

function verificationEmailHtml(code) {
  return `
<!doctype html>
<html>
  <body style="margin:0;padding:0;background:#f4f5f7;font-family:Arial,Helvetica,sans-serif;color:#17181b;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="padding:32px 16px;background:#f4f5f7;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
            style="max-width:520px;background:#ffffff;border:1px solid #e5e7eb;border-radius:18px;">
            <tr>
              <td style="padding:34px;">
                <div style="font-size:22px;font-weight:800;margin-bottom:24px;">SiteFlow</div>
                <h1 style="font-size:25px;line-height:1.2;margin:0 0 12px;">Verify your email</h1>
                <p style="font-size:15px;line-height:1.6;color:#60646c;margin:0 0 24px;">
                  Enter this code in SiteFlow to finish creating your account.
                </p>
                <div style="font-size:34px;font-weight:800;letter-spacing:8px;text-align:center;
                  padding:20px;border-radius:14px;background:#f5f3ff;border:1px solid #e5e0ff;margin-bottom:22px;">
                  ${code}
                </div>
                <p style="font-size:13px;line-height:1.6;color:#767b84;margin:0;">
                  This code expires in 10 minutes. If you didn't request it, you can ignore this email.
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
        "Authorization": `Bearer ${AGENTMAIL_API_KEY}`,
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
    console.error("AgentMail error:", response.status, details);
    throw new Error("Could not send verification email.");
  }

  return response.json();
}

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "siteflow-verification",
    agentmailConfigured: Boolean(AGENTMAIL_API_KEY)
  });
});

app.post("/api/send-verification", sendLimiter, async (req, res) => {
  const email = normalizeEmail(req.body?.email);

  if (!isValidEmail(email)) {
    return res.status(400).json({
      ok: false,
      error: "Enter a valid email address."
    });
  }

  const existing = verificationRequests.get(email);
  const now = Date.now();

  if (existing && now - existing.lastSentAt < SEND_COOLDOWN_MS) {
    const retryAfter = Math.ceil(
      (SEND_COOLDOWN_MS - (now - existing.lastSentAt)) / 1000
    );

    return res.status(429).json({
      ok: false,
      error: `Please wait ${retryAfter} seconds before requesting another code.`,
      retryAfter
    });
  }

  const code = createCode();

  verificationRequests.set(email, {
    codeHash: hashCode(email, code),
    expiresAt: now + CODE_TTL_MS,
    lastSentAt: now,
    attempts: 0
  });

  try {
    await sendWithAgentMail(email, code);

    return res.json({
      ok: true,
      message: "Verification code sent.",
      expiresIn: CODE_TTL_MS / 1000,
      resendAfter: SEND_COOLDOWN_MS / 1000
    });
  } catch (error) {
    verificationRequests.delete(email);
    console.error(error);

    return res.status(502).json({
      ok: false,
      error: "We couldn't send the verification email. Please try again."
    });
  }
});

app.post("/api/verify-code", verifyLimiter, (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const code = String(req.body?.code || "").replace(/\D/g, "");

  if (!isValidEmail(email) || !/^\d{6}$/.test(code)) {
    return res.status(400).json({
      ok: false,
      error: "Enter your email and a 6-digit verification code."
    });
  }

  const record = verificationRequests.get(email);

  if (!record) {
    return res.status(400).json({
      ok: false,
      error: "No active verification code was found. Request a new one."
    });
  }

  if (Date.now() > record.expiresAt) {
    verificationRequests.delete(email);
    return res.status(400).json({
      ok: false,
      error: "That code has expired. Request a new one."
    });
  }

  record.attempts += 1;

  if (record.attempts > MAX_ATTEMPTS) {
    verificationRequests.delete(email);
    return res.status(429).json({
      ok: false,
      error: "Too many incorrect attempts. Request a new code."
    });
  }

  const suppliedHash = hashCode(email, code);

  if (!safeEqual(record.codeHash, suppliedHash)) {
    return res.status(400).json({
      ok: false,
      error: "That verification code is incorrect.",
      attemptsRemaining: Math.max(0, MAX_ATTEMPTS - record.attempts)
    });
  }

  verificationRequests.delete(email);

  return res.json({
    ok: true,
    verified: true,
    email
  });
});

// Clean up expired codes periodically.
setInterval(() => {
  const now = Date.now();
  for (const [email, record] of verificationRequests.entries()) {
    if (now > record.expiresAt) {
      verificationRequests.delete(email);
    }
  }
}, 60 * 1000).unref();

app.listen(PORT, () => {
  console.log(`SiteFlow server running on port ${PORT}`);
});
