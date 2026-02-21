# EyesAndEars

## Prototype overview

EyesAndEars is a prototype "on-demand Copilot" for screen issues.

- You press `Numpad 1` to capture the current screen.
- The screenshot is sent to Gemini with a strict prompt to return only the direct fix/answer.
- The app then lets you type naturally, but each keypress outputs the next character from the generated answer.
- This gives a controlled "type-every-letter" flow instead of auto-pasting full text at once.

## Local run

1. Run:
   - `run-local.cmd`

On first launch, the app asks you to create:
- an app password
- your Gemini API key

Optional: you can still provide the key via `EYESANDEARS_API_KEY`.
After setup, the CMD window auto-hides and the app continues in background with a tray icon.

## Security notes

- App password is stored as salted PBKDF2-SHA256 hash.
- On Windows, Gemini API key is stored with DPAPI encryption (user-bound).
- Legacy plaintext API keys are automatically migrated to DPAPI.
- `Numpad 9` triggers app exit and winget uninstall only when a sanitized package ID is detected.

## Hotkeys

- `Numpad 1`: Capture / Pause / Resume
- `Numpad 0`: Hide/Show indicator
- `Numpad 2`: Clear chat context
- `Numpad 9`: Exit and trigger `winget uninstall` (when launched from winget install)

## Winget packaging

See `packaging/winget/README.md`.

## End-user winget commands

- Install: `winget install eyesandears`
- Fallback install: `winget install --id FediMust.EyesAndEars -e`
- Uninstall (full portable cleanup): `winget uninstall --id FediMust.EyesAndEars -e --purge`

When launched from a winget install, pressing `Numpad 9` exits and triggers uninstall automatically.
