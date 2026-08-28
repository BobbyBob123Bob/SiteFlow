# SiteFlow — Builder + Inbox

This build includes the visual SiteFlow editor, AgentMail email verification, editable elements, working YouTube/Vimeo video embeds, and a built-in form-submission Inbox.

## Railway setup

1. Deploy this folder from GitHub to Railway.
2. In the SiteFlow service Variables, keep/add:
   - `AGENTMAIL_API_KEY`
   - `AGENTMAIL_INBOX=siteflow.verify@agentmail.to`
   - `VERIFICATION_SECRET=<a long random secret>`
3. In the same Railway project, add a **PostgreSQL** database service. Railway normally exposes `DATABASE_URL` to connected services; if it is not automatically available to the SiteFlow service, add a `DATABASE_URL` variable referencing the PostgreSQL service connection URL.
4. Redeploy SiteFlow.
5. Open `/api/health`. `databaseConfigured` should be `true` for persistent inbox storage.

## How the Inbox works

When the owner is signed into SiteFlow, the editor creates a private inbox key and registers the current workspace with the backend. Downloaded/previewed SiteFlow websites contain only the public workspace ID, never the private inbox key.

Visitors submit a Form element -> `/api/form-submit` stores the message -> the owner opens **Inbox** in SiteFlow to read it.

Inbox supports unread/read state, search, Inbox/Unread/Archived filters, archiving, deleting, timestamps, sender details, form/page details, and a Reply-by-email action.

If PostgreSQL is not configured, SiteFlow still starts and the Inbox works temporarily in memory, but messages will be lost when Railway restarts the service. Add PostgreSQL for permanent storage.

## Form element

Select a Form in the editor to configure its form name, inbox subject, success message, placeholders, button label, width, and field radius. Exported/downloaded sites automatically send submissions back to the Railway-hosted SiteFlow inbox API.

## Security notes

- Never commit the AgentMail API key to GitHub.
- The private SiteFlow inbox key stays in the owner's browser storage and is not embedded into exported sites.
- Form submission endpoints are rate-limited and validate message/email fields.
