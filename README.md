# EyesAndEars

Desktop app + subscription licensing platform.

## What changed

- Desktop startup now includes:
  - `Use Your Own API Key` (active)
  - `Subscription Code (Coming Soon)` (disabled for normal users)
- Startup UI now includes indicator blob size selection:
  - `Very Small`, `Small`, `Medium`, `Large`
  - live preview in the sign-in window
- Checkout flow now uses Flouci (Tunisian payment gateway).
- Subscription code mode authenticates with licensing server.
- One active desktop session per license is enforced server-side.
- Tray-first desktop UX with no persistent console/taskbar clutter.

## Project parts

- Desktop app: root (`import os.py`)
- Web/backend/admin/licensing platform: [`platform/README.md`](platform/README.md)

## Desktop local run

1. Start backend platform first (see `platform/README.md`).
2. Run desktop app:
   - `run-local.cmd`

Or manually:

```bat
python -m pip install -r requirements.txt
python "import os.py"
```

Server URL is currently hardcoded in `import os.py`:
- `HARDCODED_SERVER_URL = "http://localhost:8000"`
- Update this constant directly before release/deployment (for example your Azure endpoint).

## Website/Backend quick run

From repo root:

```bat
run-platform.cmd
```

This script installs dependencies, starts DB/mail services (Docker if available), runs migrations, and launches the site.

On each launch, the app prompts for:
- `Use Your Own API Key`
- `Subscription Code (Coming Soon)` (publicly locked for now)

The app stores code/API key with DPAPI on Windows (fallback plaintext only on non-Windows).

## Hotkeys

- `Numpad 1`: Capture / Pause / Resume typing output
- `Numpad 0`: Toggle indicator visibility
- `Numpad 2`: Clear pending answer
- `Numpad 3`: Paste remaining answer instantly
- `Numpad 4`: Reload last answer
- `Numpad 9`: Quit (and winget self-uninstall trigger when applicable)

## Winget packaging

See `packaging/winget/README.md`.
