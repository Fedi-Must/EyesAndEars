import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


UPSTREAM_OWNER = "microsoft"
UPSTREAM_REPO = "winget-pkgs"
FORK_OWNER = "Fedi-Must"
PACKAGE_IDENTIFIER = "FediMust.EyesAndEars"
PACKAGE_VERSION = "2.1.0"
BASE_BRANCH = "master"
MANIFEST_LOCAL_FILES = (
    "packaging/winget/FediMust.EyesAndEars.yaml",
    "packaging/winget/FediMust.EyesAndEars.installer.yaml",
    "packaging/winget/FediMust.EyesAndEars.locale.en-US.yaml",
)


def github_token_from_gcm(username):
    request_input = f"protocol=https\nhost=github.com\nusername={username}\n\n"
    result = subprocess.run(
        ["git", "credential-manager", "get"],
        input=request_input,
        text=True,
        capture_output=True,
        check=True,
    )
    token = ""
    for line in result.stdout.splitlines():
        if line.startswith("password="):
            token = line.split("=", 1)[1].strip()
            break
    if not token:
        raise RuntimeError("Could not read GitHub token from Git Credential Manager.")
    return token


def github_request(method, url, token, data_obj=None, accept="application/vnd.github+json"):
    headers = {
        "Accept": accept,
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "eyesandears-winget-pr-script",
    }
    payload = None
    if data_obj is not None:
        payload = json.dumps(data_obj).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url=url, method=method, data=payload, headers=headers)
    with urllib.request.urlopen(req) as resp:
        body = resp.read()
    if not body:
        return None
    return json.loads(body.decode("utf-8"))


def count_line_endings(raw_bytes):
    crlf = raw_bytes.count(b"\r\n")
    lf_only = raw_bytes.count(b"\n") - crlf
    cr_only = raw_bytes.count(b"\r") - crlf
    return crlf, lf_only, cr_only


def normalize_manifest_bytes(raw_bytes):
    text = raw_bytes.decode("utf-8-sig")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if not text.endswith("\n"):
        text += "\n"
    return text.encode("utf-8")


def normalize_manifest_file_in_place(local_path):
    with open(local_path, "rb") as f:
        raw = f.read()
    normalized = normalize_manifest_bytes(raw)
    if normalized != raw:
        with open(local_path, "wb") as f:
            f.write(normalized)
    return normalized.decode("utf-8")


def parse_yaml_scalar(value):
    result = str(value or "").strip()
    if result.startswith(("'", '"')) and result.endswith(("'", '"')) and len(result) >= 2:
        if result[0] == result[-1]:
            result = result[1:-1]
    return result


def extract_manifest_value(manifest_text, key_name):
    pattern = rf"(?mi)^\s*{re.escape(key_name)}\s*:\s*(.+?)\s*$"
    match = re.search(pattern, manifest_text)
    if not match:
        raise RuntimeError(f"Missing field '{key_name}' in manifest.")
    raw_value = str(match.group(1)).split(" #", 1)[0]
    return parse_yaml_scalar(raw_value)


def run_winget_validate(manifest_local_paths):
    winget_path = shutil.which("winget")
    if not winget_path:
        print("warning=winget executable not found; skipped local validate step.")
        return
    with tempfile.TemporaryDirectory(prefix="eyesandears-winget-") as temp_dir:
        for local_path in manifest_local_paths:
            target_path = os.path.join(temp_dir, os.path.basename(local_path))
            with open(local_path, "rb") as src, open(target_path, "wb") as dst:
                dst.write(src.read())
        result = subprocess.run(
            [winget_path, "validate", "--manifest", temp_dir],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            details = []
            if result.stdout:
                details.append(result.stdout.strip())
            if result.stderr:
                details.append(result.stderr.strip())
            joined = "\n".join(part for part in details if part).strip()
            raise RuntimeError(f"winget validate failed.\n{joined}")


def validate_local_manifests(package_version):
    manifest_text_by_path = {}
    for local_path in MANIFEST_LOCAL_FILES:
        if not os.path.exists(local_path):
            raise FileNotFoundError(f"Missing local file: {local_path}")
        text = normalize_manifest_file_in_place(local_path)
        manifest_text_by_path[local_path] = text
        raw = text.encode("utf-8")
        crlf, lf_only, cr_only = count_line_endings(raw)
        if cr_only > 0:
            raise RuntimeError(f"Invalid line endings in {local_path} (CR-only={cr_only}).")
        if crlf > 0 and lf_only > 0:
            raise RuntimeError(f"Mixed line endings in {local_path} (CRLF={crlf}, LF={lf_only}).")

    version_path = MANIFEST_LOCAL_FILES[0]
    installer_path = MANIFEST_LOCAL_FILES[1]
    locale_path = MANIFEST_LOCAL_FILES[2]

    for path in (version_path, installer_path, locale_path):
        text = manifest_text_by_path[path]
        package_id = extract_manifest_value(text, "PackageIdentifier")
        if package_id != PACKAGE_IDENTIFIER:
            raise RuntimeError(f"Unexpected PackageIdentifier in {path}: {package_id}")
        manifest_version = extract_manifest_value(text, "PackageVersion")
        if manifest_version != package_version:
            raise RuntimeError(
                f"PackageVersion mismatch in {path}: expected {package_version}, found {manifest_version}"
            )

    installer_text = manifest_text_by_path[installer_path]
    installer_url = extract_manifest_value(installer_text, "InstallerUrl")
    installer_sha = extract_manifest_value(installer_text, "InstallerSha256").upper()
    if not re.fullmatch(r"[A-F0-9]{64}", installer_sha):
        raise RuntimeError("InstallerSha256 must be a 64-character uppercase hex digest.")
    expected_url_suffix = f"/releases/download/v{package_version}/EyesAndEars-{package_version}-x64.exe"
    if not installer_url.endswith(expected_url_suffix):
        raise RuntimeError(
            "InstallerUrl does not target the expected release asset.\n"
            f"expected suffix: {expected_url_suffix}\n"
            f"actual: {installer_url}"
        )

    local_asset_path = os.path.join("dist", f"EyesAndEars-{package_version}-x64.exe")
    if os.path.exists(local_asset_path):
        with open(local_asset_path, "rb") as f:
            local_asset_hash = hashlib.sha256(f.read()).hexdigest().upper()
        if local_asset_hash != installer_sha:
            raise RuntimeError(
                "InstallerSha256 does not match local dist artifact.\n"
                f"manifest: {installer_sha}\n"
                f"local:    {local_asset_hash}\n"
                f"artifact: {local_asset_path}"
            )
    else:
        print(f"warning=local artifact not found, skipped hash cross-check: {local_asset_path}")

    run_winget_validate(MANIFEST_LOCAL_FILES)


def ensure_fork_exists(token):
    fork_url = f"https://api.github.com/repos/{UPSTREAM_OWNER}/{UPSTREAM_REPO}/forks"
    try:
        github_request("POST", fork_url, token)
    except urllib.error.HTTPError as e:
        # 202 can be returned while fork is being created; 403/422 may indicate already exists.
        if e.code not in (202, 403, 422):
            raise

    # Wait until fork is visible.
    check_url = f"https://api.github.com/repos/{FORK_OWNER}/{UPSTREAM_REPO}"
    for _ in range(30):
        try:
            github_request("GET", check_url, token)
            return
        except urllib.error.HTTPError as e:
            if e.code == 404:
                time.sleep(2)
                continue
            raise
    raise RuntimeError("Fork did not become available in time.")


def get_base_sha(token):
    ref_url = f"https://api.github.com/repos/{UPSTREAM_OWNER}/{UPSTREAM_REPO}/git/ref/heads/{BASE_BRANCH}"
    ref = github_request("GET", ref_url, token)
    return ref["object"]["sha"]


def ensure_branch(token, branch_name, base_sha):
    create_ref_url = f"https://api.github.com/repos/{FORK_OWNER}/{UPSTREAM_REPO}/git/refs"
    payload = {"ref": f"refs/heads/{branch_name}", "sha": base_sha}
    try:
        github_request("POST", create_ref_url, token, payload)
    except urllib.error.HTTPError as e:
        if e.code != 422:
            raise


def get_existing_file_sha(token, path, branch_name):
    encoded_path = urllib.parse.quote(path)
    url = f"https://api.github.com/repos/{FORK_OWNER}/{UPSTREAM_REPO}/contents/{encoded_path}?ref={branch_name}"
    try:
        file_obj = github_request("GET", url, token)
        return file_obj.get("sha", "")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return ""
        raise


def read_file_for_upload(local_path):
    with open(local_path, "rb") as f:
        raw = f.read()
    if local_path.lower().endswith((".yaml", ".yml")):
        return normalize_manifest_bytes(raw)
    return raw


def upsert_file(token, branch_name, repo_path, local_path, message):
    upload_bytes = read_file_for_upload(local_path)
    content = base64.b64encode(upload_bytes).decode("ascii")

    encoded_path = urllib.parse.quote(repo_path)
    url = f"https://api.github.com/repos/{FORK_OWNER}/{UPSTREAM_REPO}/contents/{encoded_path}"
    payload = {
        "message": message,
        "content": content,
        "branch": branch_name,
    }
    existing_sha = get_existing_file_sha(token, repo_path, branch_name)
    if existing_sha:
        payload["sha"] = existing_sha
    github_request("PUT", url, token, payload)


def create_or_get_pr(token, branch_name, package_version):
    create_pr_url = f"https://api.github.com/repos/{UPSTREAM_OWNER}/{UPSTREAM_REPO}/pulls"
    title = f"New package: {PACKAGE_IDENTIFIER} {package_version}"
    body = (
        f"## Summary\n"
        f"- Adds `{PACKAGE_IDENTIFIER}` version `{package_version}`\n"
        f"- Installer type: portable\n"
        f"- Installer source: GitHub release asset\n"
    )
    payload = {
        "title": title,
        "head": f"{FORK_OWNER}:{branch_name}",
        "base": BASE_BRANCH,
        "body": body,
    }
    try:
        pr = github_request("POST", create_pr_url, token, payload)
        return pr["html_url"]
    except urllib.error.HTTPError as e:
        if e.code != 422:
            raise

    # PR likely already exists.
    list_url = (
        f"https://api.github.com/repos/{UPSTREAM_OWNER}/{UPSTREAM_REPO}/pulls"
        f"?state=open&head={urllib.parse.quote(FORK_OWNER + ':' + branch_name)}"
    )
    pulls = github_request("GET", list_url, token)
    if pulls:
        return pulls[0]["html_url"]
    raise RuntimeError("Could not create or locate PR.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", default=FORK_OWNER)
    parser.add_argument("--version", default=PACKAGE_VERSION)
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="Validate local manifests and exit without touching GitHub.",
    )
    args = parser.parse_args()

    files = [
        (
            f"manifests/f/FediMust/EyesAndEars/{args.version}/FediMust.EyesAndEars.yaml",
            MANIFEST_LOCAL_FILES[0],
        ),
        (
            f"manifests/f/FediMust/EyesAndEars/{args.version}/FediMust.EyesAndEars.installer.yaml",
            MANIFEST_LOCAL_FILES[1],
        ),
        (
            f"manifests/f/FediMust/EyesAndEars/{args.version}/FediMust.EyesAndEars.locale.en-US.yaml",
            MANIFEST_LOCAL_FILES[2],
        ),
    ]
    validate_local_manifests(args.version)
    if args.preflight_only:
        print("preflight=ok")
        return

    token = github_token_from_gcm(args.username)
    ensure_fork_exists(token)
    base_sha = get_base_sha(token)

    branch_name = f"fedi-must-eyesandears-{args.version.replace('.', '-')}"
    ensure_branch(token, branch_name, base_sha)

    for repo_path, local_path in files:
        upsert_file(
            token,
            branch_name,
            repo_path,
            local_path,
            f"Add {PACKAGE_IDENTIFIER} {args.version}",
        )

    pr_url = create_or_get_pr(token, branch_name, args.version)
    print("pr_url=" + pr_url)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"error={exc}")
        sys.exit(1)
