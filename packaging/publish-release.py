import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request


OWNER = "Fedi-Must"
REPO = "EyesAndEars"


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
        "User-Agent": "eyesandears-release-script",
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


def github_upload_asset(upload_url, token, asset_path):
    asset_name = os.path.basename(asset_path)
    encoded_name = urllib.parse.quote(asset_name)
    target_url = f"{upload_url}?name={encoded_name}"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "eyesandears-release-script",
        "Content-Type": "application/octet-stream",
    }

    with open(asset_path, "rb") as f:
        payload = f.read()

    req = urllib.request.Request(url=target_url, method="POST", data=payload, headers=headers)
    with urllib.request.urlopen(req) as resp:
        body = resp.read()
    return json.loads(body.decode("utf-8"))


def get_or_create_release(token, tag_name):
    release_by_tag_url = f"https://api.github.com/repos/{OWNER}/{REPO}/releases/tags/{tag_name}"
    try:
        return github_request("GET", release_by_tag_url, token)
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise

    create_url = f"https://api.github.com/repos/{OWNER}/{REPO}/releases"
    payload = {
        "tag_name": tag_name,
        "name": tag_name,
        "draft": False,
        "prerelease": False,
        "generate_release_notes": True,
    }
    return github_request("POST", create_url, token, payload)


def delete_existing_asset_if_needed(token, release, asset_name):
    for asset in release.get("assets", []):
        if asset.get("name") == asset_name:
            asset_id = asset.get("id")
            if not asset_id:
                continue
            delete_url = f"https://api.github.com/repos/{OWNER}/{REPO}/releases/assets/{asset_id}"
            github_request("DELETE", delete_url, token)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", default="1.0.0")
    parser.add_argument("--username", default="Fedi-Must")
    parser.add_argument("--asset", default="dist/EyesAndEars-1.0.0-x64.exe")
    args = parser.parse_args()

    if not os.path.exists(args.asset):
        raise FileNotFoundError(f"Asset not found: {args.asset}")

    token = github_token_from_gcm(args.username)
    tag_name = f"v{args.version}"
    release = get_or_create_release(token, tag_name)

    asset_name = os.path.basename(args.asset)
    delete_existing_asset_if_needed(token, release, asset_name)

    upload_base = release["upload_url"].split("{", 1)[0]
    uploaded_asset = github_upload_asset(upload_base, token, args.asset)

    print("release_url=" + release["html_url"])
    print("asset_url=" + uploaded_asset["browser_download_url"])


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"error={exc}")
        sys.exit(1)
