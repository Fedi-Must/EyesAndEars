import argparse
import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


UPSTREAM_OWNER = "microsoft"
UPSTREAM_REPO = "winget-pkgs"
FORK_OWNER = "Fedi-Must"
PACKAGE_IDENTIFIER = "FediMust.EyesAndEars"
PACKAGE_VERSION = "1.0.0"
BASE_BRANCH = "master"


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


def upsert_file(token, branch_name, repo_path, local_path, message):
    with open(local_path, "rb") as f:
        content = base64.b64encode(f.read()).decode("ascii")

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


def create_or_get_pr(token, branch_name):
    create_pr_url = f"https://api.github.com/repos/{UPSTREAM_OWNER}/{UPSTREAM_REPO}/pulls"
    title = f"New package: {PACKAGE_IDENTIFIER} {PACKAGE_VERSION}"
    body = (
        f"## Summary\n"
        f"- Adds `{PACKAGE_IDENTIFIER}` version `{PACKAGE_VERSION}`\n"
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
    args = parser.parse_args()

    token = github_token_from_gcm(args.username)
    ensure_fork_exists(token)
    base_sha = get_base_sha(token)

    branch_name = f"fedi-must-eyesandears-{args.version.replace('.', '-')}"
    ensure_branch(token, branch_name, base_sha)

    base_path = f"manifests/f/FediMust/EyesAndEars/{args.version}"
    files = [
        (
            f"{base_path}/FediMust.EyesAndEars.yaml",
            "packaging/winget/FediMust.EyesAndEars.yaml",
        ),
        (
            f"{base_path}/FediMust.EyesAndEars.installer.yaml",
            "packaging/winget/FediMust.EyesAndEars.installer.yaml",
        ),
        (
            f"{base_path}/FediMust.EyesAndEars.locale.en-US.yaml",
            "packaging/winget/FediMust.EyesAndEars.locale.en-US.yaml",
        ),
    ]

    for repo_path, local_path in files:
        if not os.path.exists(local_path):
            raise FileNotFoundError(f"Missing local file: {local_path}")
        upsert_file(
            token,
            branch_name,
            repo_path,
            local_path,
            f"Add {PACKAGE_IDENTIFIER} {args.version}",
        )

    pr_url = create_or_get_pr(token, branch_name)
    print("pr_url=" + pr_url)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"error={exc}")
        sys.exit(1)
