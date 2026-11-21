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

## Online world prototype

Each character card has a **Start** action that opens a small top-down world
with animated low-poly 3D characters. Players on the same realm can move with
WASD/arrow keys or the on-screen touch controls and see each other's live
positions through Firebase Realtime Database. Characters resume at their last
saved world location. Idle or disconnected player presence expires, while the
character's saved location remains.

The world is an early prototype, not a production MMORPG: movement is
client-reported and there is not yet combat, progression, or an authoritative
game server. The realtime player rules are in `database.rules.json`; after
selecting the correct Firebase project, publish them with
`firebase deploy --only database` so online visibility and saved locations work.
On mobile, the game requests fullscreen landscape on entry. If the browser
blocks the automatic request, tap **Fullscreen**; orientation locking requires
a secure page and a user gesture in supported browsers.