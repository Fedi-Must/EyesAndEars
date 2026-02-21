# Winget publish checklist

1. Build the portable executable:
   - `packaging\build-portable.cmd 1.0.0`
2. Upload `dist\EyesAndEars-1.0.0-x64.exe` to a GitHub Release at:
   - `https://github.com/Fedi-Must/EyesAndEars/releases/tag/v1.0.0`
3. Copy the SHA256 from the build output.
4. Edit these files and replace placeholders:
   - `packaging/winget/FediMust.EyesAndEars.yaml`
   - `packaging/winget/FediMust.EyesAndEars.installer.yaml`
   - `packaging/winget/FediMust.EyesAndEars.locale.en-US.yaml`
5. Validate manifests locally:
   - `winget validate --manifest packaging\winget`
6. Test local install and uninstall:
   - `packaging\winget\test-install-uninstall.cmd FediMust.EyesAndEars`
7. Submit the three manifest files in a PR to:
   - `https://github.com/microsoft/winget-pkgs`

After merge, anyone can install with:
- `winget install eyesandears`
- fallback: `winget install --id FediMust.EyesAndEars -e`

And uninstall with:
- `winget uninstall --id FediMust.EyesAndEars -e --purge`

Notes:
- `--purge` removes package files for portable apps.
- If a user wants to keep package files during uninstall, they can use `--preserve` instead.
- No Python runtime is required for end users (the EXE is self-contained).
- On first launch, the app prompts for password and Gemini API key.
- When run from winget, `Numpad 9` schedules `winget uninstall --purge` automatically.
