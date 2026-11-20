# SENTINEL-AI frontend redesign

This is a frontend-only replacement. The original backend is unchanged.

## Install
1. Back up your current `sentinel-ai/frontend` folder.
2. Copy the included `frontend/src` files and `frontend/vite.config.ts` into your existing frontend directory, or replace the frontend directory after backing it up.
3. From `sentinel-ai/frontend`, run `npm install` (if needed) and `npm run dev`.
4. Keep your existing FastAPI server running on 127.0.0.1:8000.

## Notes
- Existing JARVIS, Defense Center and Active Defense React components are retained.
- New command-center overview uses actual telemetry, alerts and network snapshot data.
- The animated radar is a decorative monitoring indicator, not a threat-detection claim.
- Network and alert values are stored snapshots; not guaranteed current.
- Security Alerts table header Source column is corrected.
- TypeScript typecheck passed in the container. Vite bundling could not be verified on Linux because the uploaded node_modules are macOS-specific. Run npm install on your Mac.
