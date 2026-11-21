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
character's saved location remains. Static terrain is cached in bounded chunks,
and mobile devices use a lower render resolution to reduce frame cost. Player
movement eases in and out locally, while remote movement is interpolated and
briefly predicted between realtime updates.

The world is an early prototype, not a production MMORPG: movement is
client-reported and combat is not validated by an authoritative game server.
The realtime player, monster, skill, and cooldown rules are in
`database.rules.json`; after selecting the correct Firebase project, publish
them with `firebase deploy --only database`.

Skill cooldowns are read live from
`gameConfig/skills/{skillId}/cooldownMs` in Firebase Realtime Database, in
milliseconds. Missing or invalid values use each skill's built-in default;
valid values range from 250 to 120,000 ms. For example, set
`gameConfig/skills/vanguard_cleave/cooldownMs` to `1200` to make Cleave's
cooldown 1.2 seconds. Only accounts whose `users/{uid}/role` is `gamemaster`
can write this configuration. Skill animations and the caster's skill label
are shared with players in the same realm. Click or tap a living monster to
lock it as your target; pressing a skill approaches until it is in range, then
casts. Manual movement cancels the approach. This does not change the map.

On mobile, the game requests fullscreen landscape on entry. If the browser
blocks the automatic request, tap **Fullscreen**; orientation locking requires
a secure page and a user gesture in supported browsers.