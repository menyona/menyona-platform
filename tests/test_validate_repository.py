"""Negative regression cases for the offline repository checks."""

import contextlib
import importlib.util
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "validate_repository.py"
SPEC = importlib.util.spec_from_file_location("validate_repository", SCRIPT)
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class RepositoryChecks(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        subprocess.run(["git", "init", "--quiet", str(self.root)], check=True)
        self.plan = "# خطة المشروع\n\n" + "".join(
            f"- القرار {number:03d}، معتمد.\n" for number in range(1, 82)
        )
        self.write("PROJECT_PLAN.md", self.plan)

    def write(self, name, content, tracked=True):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
        if tracked:
            subprocess.run(["git", "-C", str(self.root), "add", "--", name], check=True)

    def errors(self):
        return validator.validate_repository(self.root)

    def assert_rejected(self, fragment):
        self.assertTrue(any(fragment in error for error in self.errors()), fragment)

    def test_valid_arabic_documents_relative_links_and_anchors(self):
        self.write("README.md", "# مرحبا\n\n[الخطة](PROJECT_PLAN.md#خطة-المشروع)\n[مرجع][plan]\n\n[plan]: PROJECT_PLAN.md\n")
        self.write("docs/page.md", "[الخطة](../PROJECT_PLAN.md)\n")
        self.assertEqual([], self.errors())

    def test_untracked_sensitive_file_is_never_read(self):
        self.write(".codex/local.json", b"\xff", tracked=False)
        self.assertEqual([], self.errors())

    def test_tracked_environment_and_credential_paths_are_rejected(self):
        for name in (".env", "docs/.env.production", "secrets/demo.txt", ".codex/demo.txt", "backup.sql"):
            with self.subTest(name=name):
                self.write(name, "placeholder\n")
                self.assert_rejected("forbidden tracked")

    def test_example_environment_has_no_secret_exemption(self):
        self.write(".env.example", "API_KEY=your-api-key-here\n")
        self.assertEqual([], self.errors())
        self.write(".env.example", "API_KEY=" + "A" * 24 + "\n")
        self.assert_rejected("possible secret")

    def test_secrets_are_redacted_in_diagnostics(self):
        examples = [
            "gh" + "p_" + "Z" * 36,
            "AK" + "IA" + "Z" * 16,
            "sk-" + "proj-" + "Z" * 40,
            "-----BEGIN " + "PRIVATE KEY-----",
        ]
        for example in examples:
            with self.subTest(kind=examples.index(example)):
                self.write("example.txt", example + "\n")
                errors = self.errors()
                self.assertTrue(any("possible secret" in error for error in errors))
                self.assertNotIn(example, "\n".join(errors))

    def test_missing_and_untracked_link_targets_rejected(self):
        self.write("README.md", "[missing](missing.md)\n")
        self.write("missing.md", "# Not tracked\n", tracked=False)
        self.assert_rejected("not a validated tracked file")

    def test_reference_link_target_is_checked(self):
        self.write("README.md", "[missing][target]\n\n[target]: missing.md\n")
        self.assert_rejected("not a validated tracked file")

    def test_repository_escape_and_encoded_escape_are_rejected(self):
        for target in ("../outside.md", "%2e%2e/outside.md", "docs/../../outside.md"):
            with self.subTest(target=target):
                self.write("README.md", f"[bad]({target})\n")
                self.assert_rejected("escapes repository")

    def test_absolute_file_and_script_links_are_rejected(self):
        for target in ("/etc/passwd", "file:///etc/passwd", "javascript:evil", "%2fetc/passwd", "//example.com/file"):
            with self.subTest(target=target):
                self.write("README.md", f"[bad]({target})\n")
                self.assert_rejected("unsupported or absolute")

    def test_missing_anchor_is_rejected(self):
        self.write("README.md", "[wrong](PROJECT_PLAN.md#missing)\n")
        self.assert_rejected("anchor does not exist")

    def test_fenced_examples_are_not_resolved_as_links(self):
        self.write("README.md", "```markdown\n[example](missing.md)\n```\n")
        self.assertEqual([], self.errors())

    def test_external_links_are_not_fetched(self):
        self.write("README.md", "[external](https://invalid.invalid/nonexistent)\n")
        self.assertEqual([], self.errors())

    def test_tracked_symlink_rejected_without_reading_target(self):
        target = self.root.parent / (self.root.name + "-outside")
        target.write_bytes(b"\xff")
        self.addCleanup(target.unlink)
        (self.root / "linked.md").symlink_to(target)
        subprocess.run(["git", "-C", str(self.root), "add", "--", "linked.md"], check=True)
        self.assert_rejected("only regular tracked files")

    def test_regular_tracked_file_replaced_with_symlink_is_rejected(self):
        self.write("linked.md", "# Original\n")
        (self.root / "linked.md").unlink()
        (self.root / "linked.md").symlink_to("PROJECT_PLAN.md")
        self.assert_rejected("symlink file or parent")

    def test_utf8_bom_nul_crlf_and_whitespace_are_rejected(self):
        cases = [(b"\xff", "UTF-8"), (b"\xef\xbb\xbftext\n", "BOM"),
                 (b"text\x00\n", "NUL"), (b"text\r\n", "non-LF"),
                 (b"text \n", "trailing whitespace"), (b"text", "final newline")]
        for content, message in cases:
            with self.subTest(message=message):
                self.write("invalid.txt", content)
                self.assert_rejected(message)

    def test_duplicate_missing_and_reordered_decisions_rejected(self):
        variants = [self.plan.replace("002", "001"),
                    self.plan.replace("- القرار 002، معتمد.\n", ""),
                    self.plan.replace("001", "999")]
        for plan in variants:
            with self.subTest(index=variants.index(plan)):
                self.write("PROJECT_PLAN.md", plan)
                self.assert_rejected("unique, ordered and contiguous")

    def test_undefined_decision_reference_rejected(self):
        self.write("README.md", "حسب القرار 099.\n")
        self.assert_rejected("undefined decision")

    def test_future_contiguous_decision_is_allowed(self):
        self.write("PROJECT_PLAN.md", self.plan + "- القرار 082، معتمد.\n")
        self.write("README.md", "حسب القرار 082.\n")
        self.assertEqual([], self.errors())

    def test_cli_failure_does_not_echo_subprocess_output(self):
        output = io.StringIO()
        with patch.object(validator, "tracked_entries", side_effect=ValueError("sensitive detail")):
            with patch("sys.argv", [str(SCRIPT), "--root", str(self.root)]):
                with contextlib.redirect_stderr(output):
                    self.assertEqual(1, validator.main())
        self.assertNotIn("sensitive detail", output.getvalue())


if __name__ == "__main__":
    unittest.main()
