# Winget publish checklist

1. Build the portable executable:
   - `packaging\build-portable.cmd 2.2.0`
2. Upload `dist\EyesAndEars-2.2.0-x64.exe` to a GitHub Release at:
   - `https://github.com/Fedi-Must/EyesAndEars/releases/tag/v2.2.0`
3. Copy the SHA256 from the build output.
4. Edit these files and replace placeholders:
   - `packaging/winget/FediMust.EyesAndEars.yaml`
   - `packaging/winget/FediMust.EyesAndEars.installer.yaml`
   - `packaging/winget/FediMust.EyesAndEars.locale.en-US.yaml`
5. Run strict local preflight (line endings + hash + URL + `winget validate`):
   - `python packaging\winget\submit-winget-pr.py --version 2.2.0 --preflight-only`
6. Test local install and uninstall:
   - `packaging\winget\test-install-uninstall.cmd FediMust.EyesAndEars`
7. Submit/update the PR to `microsoft/winget-pkgs`:
   - `python packaging\winget\submit-winget-pr.py --version 2.2.0`
8. Verify PR labels include `Validation-Completed` and do not include `Validation-Line-Endings-Error`.

The automation script normalizes manifest line endings before upload to prevent mixed EOL failures.

If you need to submit manually, ensure all `.yaml` files use one consistent newline style (no mixed CRLF/LF).

Alternative manual submission target:
   - `https://github.com/microsoft/winget-pkgs`

After merge, install with:
- `winget install eyesandears`
- fallback: `winget install --id FediMust.EyesAndEars -e`

Uninstall with:
- `winget uninstall --id FediMust.EyesAndEars -e --purge`

Notes:
- `--purge` removes package files for portable apps.
- If a user wants to keep package files during uninstall, they can use `--preserve` instead.
- No Python runtime is required for end users (the EXE is self-contained).
- On first launch, the app prompts for auth mode and credentials.
- After setup prompts, the CMD window hides and the app runs with a tray icon.
- When run from winget, `Numpad 9` schedules `winget uninstall --purge` automatically.
