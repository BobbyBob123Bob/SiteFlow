# SiteFlow — Complete Railway + AgentMail Project

This package includes your updated SiteFlow `index.html` plus the Node.js backend needed to send real verification emails with AgentMail.

## Folder structure

```text
SiteFlow_Railway_Complete/
├── public/
│   └── index.html
├── server.js
├── package.json
├── .env.example
├── .gitignore
├── railway.json
└── README.md
```

## Railway deployment

1. Upload/push this whole folder to a GitHub repository, then deploy that repository on Railway.
2. In Railway, open the service and go to **Variables**.
3. Add:
   - `AGENTMAIL_API_KEY` = your real AgentMail API key
   - `AGENTMAIL_INBOX` = `siteflow.dont.reply@agentmail.to`
   - `VERIFICATION_SECRET` = a long random secret
4. Deploy/redeploy.
5. Generate a Railway public domain for the service.

Railway supplies `PORT` automatically.

## Generate VERIFICATION_SECRET

On a computer with Node.js installed:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Copy the result into Railway as `VERIFICATION_SECRET`.

## What is connected

Signup now calls:

- `POST /api/send-verification`
- `POST /api/verify-code`

The verification code is generated on the server, sent through AgentMail, expires after 10 minutes, has a resend cooldown, and has an attempt limit.

## Important security note

Never put `AGENTMAIL_API_KEY` in `public/index.html`.

The existing SiteFlow user/password system is still browser-based/local-storage authentication. This email-verification upgrade protects the AgentMail key and verifies email ownership, but for a production app, user accounts and password hashes should eventually be moved into a real server-side database/authentication system.

## Editor upgrade included

This build also includes the expanded SiteFlow visual editor:

- Searchable 25+ element library with headings, text, buttons, images, dividers, badges, icons, navbars, banners, columns, cards, stats, testimonials, pricing, FAQ, footer, gallery, video, form, lists, progress bars, socials, marquee, quotes, sections and spacers.
- Drag-to-reorder plus **Free move** positioning inside sections with saved X/Y offsets.
- On-canvas controls to move, duplicate, reorder and delete selected elements.
- Expanded button editing for text, link, colour and corner radius.
- Element alignment controls, typography controls and position controls.
- Desktop/tablet/mobile previews and editor zoom controls.
- Keyboard shortcuts: Ctrl/Cmd+S to save, Ctrl/Cmd+D to duplicate a selected element, Delete/Backspace to remove a selected element.
- Existing undo/redo, pages, local save, standalone HTML export, sign-in/sign-up, email verification and onboarding remain included.
