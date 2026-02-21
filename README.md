# EyesAndEars

## Local run

1. Run:
   - `run-local.cmd`

On first launch, the app asks you to create:
- an app password
- your Gemini API key

Optional: you can still provide the key via `EYESANDEARS_API_KEY`.

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
