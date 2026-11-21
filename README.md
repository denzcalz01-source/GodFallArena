# GodFallArena

## Deploy on Render

The Render Blueprint in `render.yaml` deploys the complete Spring Boot app,
including the frontend and `/api` endpoints, on the same origin. This avoids
the API 404s that occur when only the static files are deployed to Firebase
Hosting.

1. Push this repository to GitHub.
2. In Render, choose **New +** → **Blueprint** and connect this repository.
3. Apply the Blueprint. Render builds the Docker image and creates a secure
   `APP_JWT_SECRET` automatically.
4. In Firebase Console, add the new `*.onrender.com` hostname to
   **Authentication → Settings → Authorized domains**.
5. Open the Render URL and test registration/sign-in and API-backed pages.

The existing Firebase Hosting deployment serves static assets only. Use the
Render URL for the full application unless Firebase Hosting is later configured
to proxy requests to the backend.