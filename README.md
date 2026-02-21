# EyesAndEars

## Local run

1. Install dependencies:
   - `python -m pip install -r requirements.txt`
2. Start the app:
   - `python "import os.py"`

On first launch, the app asks you to create:
- an app password
- your Gemini API key

Optional: you can still provide the key via `EYESANDEARS_API_KEY`.

## Hotkeys

- `Numpad 1`: Capture / Pause / Resume
- `Numpad 0`: Hide/Show indicator
- `Numpad 2`: Clear chat context
- `Numpad 9`: Exit and trigger `winget uninstall` (when package ID is configured)

## Winget packaging

See `packaging/winget/README.md`.

## End-user winget commands

- Install: `winget install <YourPackageIdentifier>`
- Uninstall (full portable cleanup): `winget uninstall --id <YourPackageIdentifier> --exact --purge`

When launched from a winget install, pressing `Numpad 9` exits and triggers uninstall automatically.
