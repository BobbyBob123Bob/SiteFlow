# SiteFlow

Complete Railway-ready SiteFlow visual website builder.

## Deploy with GitHub + Railway
1. Upload every file in this folder to your GitHub repository.
2. Connect the repository to Railway.
3. In Railway > Variables add:
   - `AGENTMAIL_API_KEY` = your AgentMail API key
   - `AGENTMAIL_INBOX` = `siteflow.verify@agentmail.to`
   - `VERIFICATION_SECRET` = a long random secret
4. Deploy. Railway will run `npm start`.
5. Generate a Railway public domain under Networking.

Do not commit your real API key or verification secret to GitHub.

## Editor
Every element now has its own relevant inspector controls. Video supports YouTube, YouTube Shorts and Vimeo URLs. Use Free Move for visual offsets, or the Up/Down controls to reorder elements.
