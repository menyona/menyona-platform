#!/usr/bin/env python3
"""Validate a native GitHub security review without executing pull-request code.

This supplements mandatory CODEOWNER approval. A GitHub Actions status alone
does not prove workflow provenance and must not replace that native protection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener


REVIEWER = "dukkanai"
CONTEXT = "security-review"
WORKFLOW_PATH = ".github/workflows/ci.yml"
REQUIRED_TESTS = frozenset({
    "repository-validation", "security-regressions", "independent-security-review",
})
REVIEW_FIELDS = frozenset({
    "schema_version", "decision", "role", "repository_id", "repository",
    "pull_request", "head_sha", "head_tree", "base_sha", "policy_sha256",
    "issued_at", "expires_at", "tests",
})
SHA = re.compile(r"[0-9a-f]{40}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


class GateError(Exception):
    """A safe, fixed error message that never includes credentials or PR text."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key rejected")
        result[key] = value
    return result


def strict_json(text: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              GateError("Non-finite JSON value rejected")))
    except (ValueError, TypeError, RecursionError) as exc:
        raise GateError("Invalid JSON data") from exc


def utc_time(value: Any) -> datetime:
    require(isinstance(value, str) and bool(re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value)),
        "Timestamp must use UTC seconds ending in Z")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise GateError("Invalid UTC timestamp") from exc


def integer(value: Any) -> bool:
    return type(value) is int and value > 0


def validate_review(reviews: list[dict[str, Any]], expected: dict[str, Any],
                    now: datetime) -> tuple[int, str]:
    """Only the latest actual native review by the configured owner counts."""
    owner_reviews = [r for r in reviews if r.get("user", {}).get("login") == REVIEWER]
    require(bool(owner_reviews), "Required owner review is missing")
    require(all(integer(r.get("id")) for r in owner_reviews), "Invalid review identity")
    review = max(owner_reviews, key=lambda r: r["id"])
    require(review.get("state") == "APPROVED", "Latest owner review is not APPROVED")
    require(review.get("user", {}).get("type") == "User", "Reviewer must be a user")
    require(review.get("author_association") in {"OWNER", "MEMBER", "COLLABORATOR"},
            "Reviewer association is not authorized")
    require(review.get("commit_id") == expected["head_sha"], "Review is for a stale head")
    body = review.get("body")
    require(isinstance(body, str) and len(body.encode("utf-8")) <= 65536,
            "Review body is missing or too large")
    data = strict_json(body)
    require(isinstance(data, dict) and set(data) == REVIEW_FIELDS,
            "Review schema fields do not match")
    require(type(data["schema_version"]) is int and data["schema_version"] == 1,
            "Unsupported review schema")
    require(data["decision"] == "PASS" and data["role"] == "security_reviewer",
            "Independent reviewer PASS is required")
    require(integer(data["repository_id"]) and integer(data["pull_request"]),
            "Invalid repository or pull request identity")
    for field, value in expected.items():
        require(data.get(field) == value, "Review does not match current repository state")
    issued = utc_time(data["issued_at"])
    expires = utc_time(data["expires_at"])
    submitted = utc_time(review.get("submitted_at"))
    require(issued <= submitted <= now < expires, "Review is expired or has a future timestamp")
    require(timedelta(0) < expires - issued <= timedelta(hours=48),
            "Review validity must not exceed 48 hours")
    tests = data["tests"]
    require(isinstance(tests, list) and 3 <= len(tests) <= 100, "Required tests are missing")
    names: set[str] = set()
    for test in tests:
        require(isinstance(test, dict) and set(test) == {"name", "result", "evidence"},
                "Invalid test schema")
        name, evidence = test["name"], test["evidence"]
        require(isinstance(name, str) and 0 < len(name) <= 100 and name not in names,
                "Missing or duplicate test name")
        names.add(name)
        require(test["result"] == "PASS", "A security test has not passed")
        require(isinstance(evidence, str) and 0 < len(evidence.strip()) <= 8192,
                "A security test has no bounded evidence")
    require(REQUIRED_TESTS <= names, "Required security test evidence is missing")
    return review["id"], hashlib.sha256(body.encode("utf-8")).hexdigest()


def select_ci_run(runs: list[dict[str, Any]], head: str, number: int) -> dict[str, Any]:
    candidates = [r for r in runs if r.get("head_sha") == head and (
        (r.get("event") == "pull_request" and any(
            p.get("number") == number for p in r.get("pull_requests", []))) or
        r.get("event") == "workflow_dispatch")]
    require(bool(candidates), "No CI run is associated with this pull request head")
    require(all(integer(r.get("id")) and integer(r.get("run_number")) and
                integer(r.get("run_attempt")) for r in candidates), "Invalid CI run identity")
    return max(candidates, key=lambda r: (r["run_number"], r["id"], r["run_attempt"]))


def validate_snapshot(snapshot: dict[str, Any], repository: str, number: int,
                      policy_hash: str, trusted_base: str, now: datetime) -> tuple[Any, ...]:
    """Pure validation of GitHub metadata; PR files are neither loaded nor run."""
    try:
        repo, pr = snapshot["repository"], snapshot["pull_request"]
        require(repo["full_name"] == repository and integer(repo["id"]),
                "Unexpected repository identity")
        require(pr["number"] == number and pr["state"] == "open" and
                not pr.get("merged", False) and not pr.get("draft", False),
                "Pull request is not open and ready")
        require(pr["base"]["ref"] == "main" and
                pr["base"]["repo"]["id"] == repo["id"], "Unexpected base repository or branch")
        require(pr["head"]["repo"]["id"] == repo["id"] and
                pr["head"]["repo"]["full_name"] == repository,
                "Fork pull requests require a separate approved review path")
        head, base = pr["head"]["sha"], snapshot["main_sha"]
        require(bool(SHA.fullmatch(head)) and bool(SHA.fullmatch(base)), "Invalid commit identity")
        require(base == trusted_base == pr["base"]["sha"], "Main changed; rerun from current main")
        commit = snapshot["head_commit"]
        require(commit["sha"] == head and bool(SHA.fullmatch(commit["commit"]["tree"]["sha"])),
                "Unexpected head commit or tree")
        comparison = snapshot["comparison"]
        require(comparison["merge_base_commit"]["sha"] == base and
                comparison["status"] in {"ahead", "identical"}, "Pull request is behind current main")
        expected = {
            "repository_id": repo["id"], "repository": repository, "pull_request": number,
            "head_sha": head, "head_tree": commit["commit"]["tree"]["sha"],
            "base_sha": base, "policy_sha256": policy_hash,
        }
        review_id, body_hash = validate_review(snapshot["reviews"], expected, now)
        workflow = snapshot["workflow"]
        require(workflow["path"] == WORKFLOW_PATH and workflow["state"] == "active" and
                integer(workflow["id"]), "CI workflow identity is not trusted")
        run = select_ci_run(snapshot["runs"], head, number)
        require(run["workflow_id"] == workflow["id"] and run["path"] == WORKFLOW_PATH,
                "CI run used an unexpected workflow")
        require(run["repository"]["id"] == repo["id"] and
                run["head_repository"]["id"] == repo["id"], "CI repository identity differs")
        require(run["status"] == "completed" and run["conclusion"] == "success",
                "Latest CI run did not succeed")
        if run["event"] == "pull_request":
            links = [p for p in run["pull_requests"] if p.get("number") == number]
            require(len(links) == 1 and links[0]["head"]["sha"] == head and
                    links[0]["base"]["sha"] == base, "CI ran against a different head or base")
        else:
            require(run["event"] == "workflow_dispatch" and
                    run["actor"]["login"] == REVIEWER and
                    run["triggering_actor"]["login"] == REVIEWER and
                    run["head_branch"] == pr["head"]["ref"],
                    "Manual CI must be dispatched by the trusted owner on the PR branch")
        require(snapshot["jobs_run_id"] == run["id"] and
                snapshot["jobs_run_attempt"] == run["run_attempt"], "CI jobs are from an older attempt")
        jobs = [j for j in snapshot["jobs"] if j.get("name") == "ci-validation"]
        require(len(jobs) == 1 and jobs[0]["run_id"] == run["id"] and
                jobs[0]["status"] == "completed" and jobs[0]["conclusion"] == "success",
                "The required CI job did not succeed")
        require(integer(jobs[0]["id"]), "Invalid CI job identity")
        return (repo["id"], number, head, base, expected["head_tree"], review_id,
                body_hash, workflow["id"], run["id"], run["run_attempt"], jobs[0]["id"])
    except (KeyError, TypeError, AttributeError) as exc:
        raise GateError("Required GitHub metadata is incomplete") from exc


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: Any, msg: Any,
                         headers: Any, newurl: Any) -> None:
        raise GateError("GitHub API redirects are not allowed")


class GitHubAPI:
    def __init__(self, token: str, repository: str):
        self.token, self.repository = token, repository
        self.opener = build_opener(NoRedirect())

    def request(self, path: str, payload: dict[str, Any] | None = None) -> Any:
        require(path.startswith("/") and not path.startswith("//"), "Invalid API path")
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request("https://api.github.com" + path, data=data, headers={
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json", "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "Menyona-Security-Gate",
        })
        try:
            with self.opener.open(request, timeout=20) as response:
                body = response.read(8 * 1024 * 1024 + 1)
                require(len(body) <= 8 * 1024 * 1024, "GitHub API response is too large")
                return strict_json(body.decode("utf-8"))
        except HTTPError as exc:
            raise GateError(f"GitHub API returned HTTP {exc.code}") from None
        except (URLError, TimeoutError, UnicodeError, OSError) as exc:
            raise GateError("GitHub API request failed") from None

    def pages(self, path: str, key: str | None = None) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        for page in range(1, 21):
            separator = "&" if "?" in path else "?"
            data = self.request(path + separator + urlencode({"per_page": 100, "page": page}))
            batch = data if key is None else data.get(key)
            require(isinstance(batch, list) and all(isinstance(x, dict) for x in batch),
                    "Invalid paginated API response")
            output.extend(batch)
            if len(batch) < 100:
                return output
        raise GateError("API pagination limit reached; manual investigation required")

    def snapshot(self, number: int) -> dict[str, Any]:
        prefix = "/repos/" + self.repository
        repo = self.request(prefix)
        pr = self.request(f"{prefix}/pulls/{number}")
        head = pr.get("head", {}).get("sha", "")
        require(isinstance(head, str) and bool(SHA.fullmatch(head)), "Invalid PR head SHA")
        base = self.request(prefix + "/git/ref/heads/main")["object"]["sha"]
        require(isinstance(base, str) and bool(SHA.fullmatch(base)), "Invalid main SHA")
        workflow = self.request(prefix + "/actions/workflows/ci.yml")
        runs = self.pages(prefix + "/actions/workflows/ci.yml/runs?" + urlencode({
            "head_sha": head,
        }), "workflow_runs")
        # Missing CI still returns review metadata, so the gate can publish failure.
        try:
            run = select_ci_run(runs, head, number)
        except GateError:
            run = None
        jobs = [] if run is None else self.pages(
            f"{prefix}/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs", "jobs")
        return {
            "repository": repo, "pull_request": pr, "main_sha": base,
            "head_commit": self.request(f"{prefix}/commits/{head}"),
            "comparison": self.request(f"{prefix}/compare/{base}...{head}"),
            "reviews": self.pages(f"{prefix}/pulls/{number}/reviews"),
            "workflow": workflow, "runs": runs, "jobs": jobs,
            "jobs_run_id": None if run is None else run["id"],
            "jobs_run_attempt": None if run is None else run["run_attempt"],
        }

    def status(self, head: str, state: str, target_url: str | None) -> None:
        descriptions = {
            "pending": "Validating independent security review and current CI",
            "success": "Current owner security review and required CI verified",
            "failure": "Security approval is missing, stale, invalid, or checks failed",
        }
        payload = {"state": state, "context": CONTEXT, "description": descriptions[state]}
        if target_url:
            payload["target_url"] = target_url
        self.request(f"/repos/{self.repository}/statuses/{head}", payload)


def run_gate(api: Any, repository: str, number: int, policy_hash: str,
             trusted_base: str, target_url: str | None = None,
             clock: Any = lambda: datetime.now(timezone.utc)) -> tuple[Any, ...]:
    """Publish only against the observed head; revalidate all evidence before PASS."""
    head = None
    try:
        pr = api.request(f"/repos/{repository}/pulls/{number}")
        candidate = pr.get("head", {}).get("sha", "")
        require(isinstance(candidate, str) and bool(SHA.fullmatch(candidate)), "Invalid PR head SHA")
        head = candidate
        api.status(head, "pending", target_url)
        first = validate_snapshot(api.snapshot(number), repository, number,
                                  policy_hash, trusted_base, clock())
        require(first[2] == head, "Pull request head changed during validation")
        second = validate_snapshot(api.snapshot(number), repository, number,
                                   policy_hash, trusted_base, clock())
        require(first == second, "Review, commits, or CI changed during validation")
        api.status(head, "success", target_url)
        return second
    except Exception as exc:
        if head is not None:
            try:
                api.status(head, "failure", target_url)
            except Exception:
                # A failed API write cannot be treated as a successful review.
                print("Could not publish failure status; gate remains failed", file=sys.stderr)
        if isinstance(exc, GateError):
            raise
        raise GateError("Security gate failed closed on unexpected metadata or API error") from None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pull-request", required=True, type=int)
    parser.add_argument("--policy", default="SECURITY_REVIEW_POLICY.md")
    args = parser.parse_args()
    try:
        require(bool(REPOSITORY.fullmatch(args.repository)), "Invalid repository argument")
        require(args.pull_request > 0, "Invalid pull request number")
        require(os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and
                os.environ.get("GITHUB_REF") == "refs/heads/main" and
                os.environ.get("GITHUB_REPOSITORY") == args.repository,
                "Gate must run from the trusted main dispatch workflow")
        trusted_base = os.environ.get("GITHUB_SHA", "")
        require(bool(SHA.fullmatch(trusted_base)), "Trusted workflow SHA is missing")
        # Fixed git metadata command, in the trusted main checkout only. Never
        # checkout, import, source, or execute a file fetched from the PR.
        checkout = subprocess.run(["git", "rev-parse", "HEAD"], check=False,
                                  capture_output=True, text=True, timeout=10)
        require(checkout.returncode == 0 and checkout.stdout.strip() == trusted_base,
                "Trusted checkout does not match the dispatch workflow SHA")
        token = os.environ.get("GITHUB_TOKEN", "")
        require(bool(token), "GITHUB_TOKEN is missing")
        policy = Path(args.policy)
        require(not policy.is_symlink() and policy.is_file() and policy.stat().st_size <= 1048576,
                "Trusted policy is missing, linked, or too large")
        policy_hash = hashlib.sha256(policy.read_bytes()).hexdigest()
        target = os.environ.get("GITHUB_RUN_URL")
        if target:
            require(bool(re.fullmatch(r"https://github\.com/" + re.escape(args.repository) +
                                      r"/actions/runs/[0-9]+", target)), "Invalid workflow run URL")
        result = run_gate(GitHubAPI(token, args.repository), args.repository,
                          args.pull_request, policy_hash, trusted_base, target)
        print(f"Security gate PASS: PR {args.pull_request}, head {result[2]}, base {result[3]}")
        return 0
    except GateError as exc:
        print("Security gate FAIL: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
