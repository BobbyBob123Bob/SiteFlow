# SiteFlow Collaboration Backend

This is the backend foundation for SiteFlow Collaboration.

## Added
- Email invitations through a separate AgentMail inbox/API key
- Secure, hashed 7-day invitation tokens
- PostgreSQL tables for pending invitations and collaborators
- Owner-only invite/member management using SiteFlow's existing workspace inbox key
- Roles: `editor`, `content`, `viewer`
- Accept-invite endpoint that gives the collaborator a unique access key
- Change role, remove collaborator, revoke pending invite
- Invitation preview endpoint for the future accept-invite UI
- `/api/collaboration/me` endpoint for validating collaborator access
- In-memory fallback for development when PostgreSQL is unavailable

## Railway variables
Keep your existing variables and add:

COLLAB_AGENTMAIL_API_KEY=YOUR_SECOND_AGENTMAIL_KEY
COLLAB_AGENTMAIL_INBOX=siteflow.collaboration@agentmail.to
SITEFLOW_APP_URL=https://YOUR-SITEFLOW-DOMAIN

Do not commit either AgentMail API key to GitHub.

## Main endpoints
POST   /api/collaboration/invites
GET    /api/collaboration
GET    /api/collaboration/invites/preview?token=...
POST   /api/collaboration/invites/accept
PATCH  /api/collaboration/members/:id
DELETE /api/collaboration/members/:id
DELETE /api/collaboration/invites/:id
GET    /api/collaboration/me

The owner-only endpoints require the existing `x-siteflow-inbox-key` header and `workspaceId`.
Collaborator validation uses `x-siteflow-collab-email` and `x-siteflow-collab-key`.

This version builds the secure membership/invitation layer first. Shared project document syncing/live editing should be added after this layer is deployed and tested.
