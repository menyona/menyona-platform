"""Negative tests for approval binding, provenance, replay, and racing metadata."""

import copy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "security_gate", Path(__file__).resolve().parents[1] / "scripts" / "security_gate.py")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

REPO = "menyona/menyona-platform"
BASE, HEAD, TREE, POLICY = "a" * 40, "b" * 40, "c" * 40, "d" * 64
NOW = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)


def fixture():
    repo = {"id": 123, "full_name": REPO}
    body = {
        "schema_version": 1, "decision": "PASS", "role": "security_reviewer",
        "repository_id": 123, "repository": REPO, "pull_request": 7,
        "head_sha": HEAD, "head_tree": TREE, "base_sha": BASE,
        "policy_sha256": POLICY, "issued_at": "2026-10-17T11:00:00Z",
        "expires_at": "2026-10-18T11:00:00Z",
        "tests": [{"name": name, "result": "PASS", "evidence": "Verified fixture evidence"}
                  for name in sorted(gate.REQUIRED_TESTS)],
    }
    return {
        "repository": repo,
        "pull_request": {"number": 7, "state": "open", "merged": False, "draft": False,
                         "head": {"sha": HEAD, "ref": "ci/security", "repo": repo},
                         "base": {"sha": BASE, "ref": "main", "repo": repo}},
        "main_sha": BASE,
        "head_commit": {"sha": HEAD, "commit": {"tree": {"sha": TREE}}},
        "comparison": {"status": "ahead", "merge_base_commit": {"sha": BASE}},
        "reviews": [{"id": 10, "state": "APPROVED", "commit_id": HEAD,
                     "user": {"id": 255427171, "login": "dukkanai", "type": "User"},
                     "author_association": "OWNER", "submitted_at": "2026-10-17T11:01:00Z",
                     "body": json.dumps(body)}],
        "workflow": {"id": 21, "path": gate.WORKFLOW_PATH, "state": "active"},
        "runs": [{"id": 30, "run_number": 4, "run_attempt": 2, "workflow_id": 21,
                  "path": gate.WORKFLOW_PATH, "head_sha": HEAD, "head_branch": "ci/security",
                  "event": "pull_request", "repository": repo, "head_repository": repo,
                  "actor": {"login": "dukkanai"}, "triggering_actor": {"login": "dukkanai"},
                  "status": "completed", "conclusion": "success", "pull_requests": [
                      {"number": 7, "head": {"sha": HEAD}, "base": {"sha": BASE}}]}],
        "jobs_run_id": 30, "jobs_run_attempt": 2,
        "jobs": [{"id": 40, "run_id": 30, "name": "ci-validation",
                  "status": "completed", "conclusion": "success"}],
    }


def edit_body(snapshot, **changes):
    body = json.loads(snapshot["reviews"][0]["body"])
    body.update(changes)
    snapshot["reviews"][0]["body"] = json.dumps(body)


class FakeAPI:
    def __init__(self, snapshots, fail_success=False):
        self.snapshots = copy.deepcopy(snapshots)
        self.initial = copy.deepcopy(snapshots[0]["pull_request"])
        self.statuses = []
        self.fail_success = fail_success

    def request(self, path):
        if path != f"/repos/{REPO}/pulls/7":
            raise AssertionError("Unexpected API request")
        return copy.deepcopy(self.initial)

    def snapshot(self, number):
        if number != 7:
            raise AssertionError("Unexpected PR")
        return self.snapshots.pop(0)

    def status(self, head, state, target_url):
        self.statuses.append((head, state))
        if state == "success" and self.fail_success:
            raise gate.GateError("API unavailable")


class SecurityGateTests(unittest.TestCase):
    def validate(self, snapshot):
        return gate.validate_snapshot(snapshot, REPO, 7, POLICY, BASE, NOW)

    def reject(self, snapshot):
        with self.assertRaises(gate.GateError):
            self.validate(snapshot)

    def test_valid_native_review(self):
        self.assertEqual(self.validate(fixture())[2:5], (HEAD, BASE, TREE))

    def test_manual_ci_is_allowed_only_for_trusted_dispatch(self):
        data = fixture()
        data["runs"][0].update(event="workflow_dispatch", pull_requests=[])
        self.validate(data)
        for field in ("actor", "triggering_actor"):
            bad = copy.deepcopy(data)
            bad["runs"][0][field]["login"] = "attacker"
            self.reject(bad)
        data["runs"][0]["head_branch"] = "different-branch"
        self.reject(data)

    def test_fabricated_review_cannot_be_an_issue_comment(self):
        data = fixture()
        data["comments"] = data.pop("reviews")
        data["reviews"] = []
        self.reject(data)

    def test_missing_review(self):
        data = fixture()
        data["reviews"] = []
        self.reject(data)

    def test_wrong_owner_id_login_and_bot_are_rejected(self):
        for field, value in (("id", 999), ("login", "attacker"), ("type", "Bot"),
                             ("login", 255427171), ("type", True)):
            data = fixture()
            data["reviews"][0]["user"][field] = value
            self.reject(data)

    def test_reviewer_id_must_be_an_integer_not_bool_float_or_string(self):
        for value in (True, False, None, "255427171", 255427171.0):
            with self.subTest(value=value):
                data = fixture()
                data["reviews"][0]["user"]["id"] = value
                self.reject(data)
        data = fixture()
        del data["reviews"][0]["user"]["id"]
        self.reject(data)

    def test_association_visibility_does_not_change_stable_identity_acceptance(self):
        for association in ("OWNER", "MEMBER", "COLLABORATOR", "CONTRIBUTOR", "NONE"):
            with self.subTest(association=association):
                data = fixture()
                data["reviews"][0]["author_association"] = association
                self.validate(data)
        data = fixture()
        del data["reviews"][0]["author_association"]
        self.validate(data)

    def test_public_association_cannot_authorize_wrong_account(self):
        for association in ("CONTRIBUTOR", "NONE", "OWNER"):
            data = fixture()
            data["reviews"][0]["author_association"] = association
            data["reviews"][0]["user"]["id"] = 999
            self.reject(data)

    def test_later_inconsistent_identity_cannot_reuse_earlier_approval(self):
        for field, value in (("id", 999), ("login", "renamed-account"), ("type", "Bot")):
            data = fixture()
            later = copy.deepcopy(data["reviews"][0])
            later.update(id=11, state="CHANGES_REQUESTED")
            later["user"][field] = value
            data["reviews"].append(later)
            self.reject(data)

    def test_latest_owner_review_supersedes_earlier_approval(self):
        for state in ("DISMISSED", "CHANGES_REQUESTED", "COMMENTED", "PENDING"):
            data = fixture()
            later = copy.deepcopy(data["reviews"][0])
            later.update(id=11, state=state)
            data["reviews"].append(later)
            self.reject(data)

    def test_other_reviewer_comment_does_not_override_owner(self):
        data = fixture()
        later = copy.deepcopy(data["reviews"][0])
        later.update(id=99, state="COMMENTED")
        later["user"]["id"] = 999
        later["user"]["login"] = "reader"
        data["reviews"].append(later)
        self.validate(data)

    def test_stale_native_review_commit(self):
        data = fixture()
        data["reviews"][0]["commit_id"] = "e" * 40
        self.reject(data)

    def test_review_identity_fields_are_bound(self):
        mutations = {
            "repository_id": 999, "repository": "attacker/repo", "pull_request": 8,
            "head_sha": "e" * 40, "head_tree": "e" * 40, "base_sha": "e" * 40,
            "policy_sha256": "e" * 64, "role": "implementer", "decision": "REVIEW_REQUIRED",
            "schema_version": True,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                data = fixture()
                edit_body(data, **{field: value})
                self.reject(data)

    def test_utc_expiry_and_max_validity(self):
        for changes in (
            {"expires_at": "2026-10-17T12:00:00Z"},
            {"issued_at": "2026-10-17T12:01:00Z"},
            {"expires_at": "2026-10-20T11:00:00Z"},
            {"issued_at": "2026-10-17T11:00:00+00:00"},
            {"issued_at": "2026-19-17T11:00:00Z"},
        ):
            data = fixture()
            edit_body(data, **changes)
            self.reject(data)

    def test_duplicate_json_keys_are_rejected_at_every_level(self):
        for text in ('{"decision":"BLOCKED","decision":"PASS"}',
                     '{"tests":[{"result":"FAIL","result":"PASS"}]}'):
            with self.assertRaises(gate.GateError):
                gate.strict_json(text)
        data = fixture()
        body = data["reviews"][0]["body"]
        data["reviews"][0]["body"] = body[:-1] + ',"decision":"PASS"}'
        self.reject(data)

    def test_non_json_markdown_nan_and_unknown_fields_are_rejected(self):
        for text in ("```json\n{}\n```", "NaN", "null", "[]"):
            data = fixture()
            data["reviews"][0]["body"] = text
            self.reject(data)
        data = fixture()
        edit_body(data, forged_extra_field=True)
        self.reject(data)

    def test_tests_must_have_unique_names_pass_and_evidence(self):
        for mutation in ("missing", "duplicate", "not_run", "failure", "no_evidence"):
            data = fixture()
            body = json.loads(data["reviews"][0]["body"])
            if mutation == "missing":
                body["tests"].pop()
            elif mutation == "duplicate":
                body["tests"].append(copy.deepcopy(body["tests"][0]))
            elif mutation == "no_evidence":
                body["tests"][0]["evidence"] = "   "
            else:
                body["tests"][0]["result"] = "NOT_RUN" if mutation == "not_run" else "FAIL"
            data["reviews"][0]["body"] = json.dumps(body)
            self.reject(data)

    def test_closed_draft_wrong_base_and_fork_fail(self):
        for field, value in (("state", "closed"), ("draft", True), ("merged", True)):
            data = fixture()
            data["pull_request"][field] = value
            self.reject(data)
        for mutation in ("base_branch", "fork", "main", "merge_base"):
            data = fixture()
            if mutation == "base_branch":
                data["pull_request"]["base"]["ref"] = "develop"
            elif mutation == "fork":
                data["pull_request"]["head"]["repo"] = {"id": 999, "full_name": "fork/repo"}
            elif mutation == "main":
                data["main_sha"] = "e" * 40
            else:
                data["comparison"]["merge_base_commit"]["sha"] = "e" * 40
            self.reject(data)

    def test_wrong_head_commit_tree_and_repository_fail(self):
        data = fixture()
        data["head_commit"]["sha"] = "e" * 40
        self.reject(data)
        data = fixture()
        data["head_commit"]["commit"]["tree"]["sha"] = "e" * 40
        self.reject(data)
        data = fixture()
        data["repository"]["full_name"] = "wrong/repo"
        self.reject(data)

    def test_ci_missing_failed_pending_skipped_or_other_workflow_fail(self):
        data = fixture()
        data["runs"] = []
        self.reject(data)
        for field, value in (("conclusion", "failure"), ("conclusion", "skipped"),
                             ("status", "in_progress"), ("workflow_id", 22),
                             ("path", ".github/workflows/forged.yml"), ("head_sha", "e" * 40)):
            data = fixture()
            data["runs"][0][field] = value
            self.reject(data)

    def test_ci_job_name_alone_does_not_suffice(self):
        for field, value in (("conclusion", "skipped"), ("run_id", 99),
                             ("status", "in_progress"), ("name", "fake-ci")):
            data = fixture()
            data["jobs"][0][field] = value
            self.reject(data)
        data = fixture()
        data["jobs"].append(copy.deepcopy(data["jobs"][0]))
        self.reject(data)

    def test_ci_must_reference_matching_pr_head_and_base(self):
        for field in ("head", "base"):
            data = fixture()
            data["runs"][0]["pull_requests"][0][field]["sha"] = "e" * 40
            self.reject(data)
        data = fixture()
        data["runs"][0]["pull_requests"][0]["number"] = 8
        self.reject(data)

    def test_old_success_does_not_mask_latest_failure(self):
        data = fixture()
        failed = copy.deepcopy(data["runs"][0])
        failed.update(id=31, run_number=5, conclusion="failure")
        data["runs"].append(failed)
        self.reject(data)

    def test_old_ci_attempt_jobs_are_rejected(self):
        data = fixture()
        data["jobs_run_attempt"] = 1
        self.reject(data)

    def test_success_is_published_after_two_consistent_snapshots(self):
        api = FakeAPI([fixture(), fixture()])
        gate.run_gate(api, REPO, 7, POLICY, BASE, clock=lambda: NOW)
        self.assertEqual(api.statuses, [(HEAD, "pending"), (HEAD, "success")])

    def test_missing_review_publishes_failure(self):
        data = fixture()
        data["reviews"] = []
        api = FakeAPI([data])
        with self.assertRaises(gate.GateError):
            gate.run_gate(api, REPO, 7, POLICY, BASE, clock=lambda: NOW)
        self.assertEqual(api.statuses, [(HEAD, "pending"), (HEAD, "failure")])

    def test_head_base_review_and_ci_races_never_publish_success(self):
        for race in ("head", "base", "review", "ci"):
            first, second = fixture(), fixture()
            if race == "head":
                second["pull_request"]["head"]["sha"] = "e" * 40
            elif race == "base":
                second["main_sha"] = "e" * 40
            elif race == "review":
                second["reviews"][0]["state"] = "DISMISSED"
            else:
                second["runs"][0]["conclusion"] = "failure"
            api = FakeAPI([first, second])
            with self.assertRaises(gate.GateError):
                gate.run_gate(api, REPO, 7, POLICY, BASE, clock=lambda: NOW)
            self.assertEqual(api.statuses, [(HEAD, "pending"), (HEAD, "failure")])

    def test_replaced_approval_even_if_valid_requires_another_run(self):
        first, second = fixture(), fixture()
        second["reviews"][0]["id"] += 1
        api = FakeAPI([first, second])
        with self.assertRaises(gate.GateError):
            gate.run_gate(api, REPO, 7, POLICY, BASE, clock=lambda: NOW)
        self.assertNotIn((HEAD, "success"), api.statuses)

    def test_api_success_write_failure_is_not_reported_as_pass(self):
        api = FakeAPI([fixture(), fixture()], fail_success=True)
        with self.assertRaises(gate.GateError):
            gate.run_gate(api, REPO, 7, POLICY, BASE, clock=lambda: NOW)
        self.assertEqual(api.statuses[-1], (HEAD, "failure"))

    def test_untrusted_text_is_data_and_never_executed(self):
        data = fixture()
        body = json.loads(data["reviews"][0]["body"])
        body["tests"][0]["evidence"] = "$(touch /tmp/NEVER_EXECUTE); __import__('os').system('false')"
        data["reviews"][0]["body"] = json.dumps(body)
        with patch.object(gate.subprocess, "run", side_effect=AssertionError("PR execution attempted")):
            self.validate(data)
            api = FakeAPI([data, data])
            gate.run_gate(api, REPO, 7, POLICY, BASE, clock=lambda: NOW)

    def test_redirects_are_not_followed_with_authorization(self):
        with self.assertRaises(gate.GateError):
            gate.NoRedirect().redirect_request(None, None, 302, None, None,
                                               "https://attacker.invalid/")


if __name__ == "__main__":
    unittest.main()
