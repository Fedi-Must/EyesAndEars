# EyesAndEars

Windows desktop capture assistant with local setup UI, tray control, and release packaging.

## Public repo scope

This repository contains the open-source desktop app and packaging scripts only.

The website, admin panel, checkout flow, and licensing backend are kept private and are not part of this public repo.

## Run locally

Use:

- `run-local.cmd`

Or manually:

```bat
python -m pip install -r requirements.txt
python "eyesandears.py"
```

Server URL is currently hardcoded in `eyesandears.py`:
- `HARDCODED_SERVER_URL = "http://localhost:8000"`
- Update this constant directly before release/deployment so the desktop app points at your private backend.

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
