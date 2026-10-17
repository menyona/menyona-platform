"""Create a PR through trusted main code; never check out or run its branch."""

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "Redirect blocked", headers, fp)


def validate_inputs(repository, branch, title, actor, ref):
    if repository != "menyona/menyona-platform":
        raise ValueError("Unexpected repository")
    if actor != "dukkanai" or ref != "refs/heads/main":
        raise ValueError("Only the trusted operator may dispatch main")
    if not re.fullmatch(r"(?:work|ci-probe)/[A-Za-z0-9][A-Za-z0-9._/-]{0,150}", branch):
        raise ValueError("Invalid review branch")
    if any(part in branch for part in ("..", "//", "@{")) or branch.endswith(("/", ".", ".lock")):
        raise ValueError("Unsafe review branch")
    if not title.strip() or len(title) > 160 or any(ord(char) < 32 for char in title):
        raise ValueError("Invalid PR title")


def main():
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    branch = os.environ.get("PR_BRANCH", "")
    title = os.environ.get("PR_TITLE", "")
    validate_inputs(repository, branch, title, os.environ.get("GITHUB_ACTOR", ""), os.environ.get("GITHUB_REF", ""))
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise ValueError("Missing workflow authentication")

    def api(path, body=None):
        request = urllib.request.Request(
            "https://api.github.com/repos/" + repository + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={
                "Authorization": "Bearer " + token,
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "User-Agent": "Menyona-review-pr",
                "X-GitHub-Api-Version": "2026-03-10",
            },
        )
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
            return json.load(response)

    head = api("/branches/" + urllib.parse.quote(branch, safe=""))
    base = api("/branches/main")
    if head["commit"]["sha"] == base["commit"]["sha"]:
        raise ValueError("Review branch has no new commit")
    existing = api("/pulls?" + urllib.parse.urlencode({"state": "open", "base": "main", "head": "menyona:" + branch}))
    if existing:
        print("Existing PR:", existing[0]["html_url"])
        return
    result = api("/pulls", {
        "head": branch,
        "base": "main",
        "title": title,
        "body": "Created by the trusted main workflow at the owner's request.\n\nIndependent security review, an authenticated current-version approval, ci-validation, and security-review are required before merge. Bot authorship is administrative and is not a security approval.",
        "draft": False,
        "maintainer_can_modify": False,
    })
    print("Created PR:", result["html_url"])


if __name__ == "__main__":
    try:
        main()
    except urllib.error.HTTPError as error:
        print("GitHub PR request failed with HTTP", error.code, file=sys.stderr)
        sys.exit(1)
    except (ValueError, KeyError, urllib.error.URLError, TimeoutError) as error:
        print("PR creation blocked:", type(error).__name__, file=sys.stderr)
        sys.exit(1)
