import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("open_review_pr", Path(__file__).resolve().parents[1] / "scripts/open_review_pr.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DispatchInputTests(unittest.TestCase):
    def validate(self, **changes):
        values = dict(repository="menyona/menyona-platform", branch="work/example", title="Review CI", actor="dukkanai", ref="refs/heads/main")
        values.update(changes)
        return MODULE.validate_inputs(**values)

    def test_only_trusted_dispatch_context(self):
        self.validate()
        for values in ({"repository": "outsider/repo"}, {"actor": "attacker"}, {"ref": "refs/heads/work/untrusted"}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.validate(**values)

    def test_branch_cannot_inject_or_escape(self):
        for branch in ("main", "work/../main", "work/x?head=main", "work/x\nmain", "work/a;id", "work/a$(id)", "work/.hidden", "work/a//b", "work/x.lock"):
            with self.subTest(branch=branch), self.assertRaises(ValueError):
                self.validate(branch=branch)

    def test_title_is_bounded_single_line_data(self):
        for title in ("", " ", "x" * 161, "a\nb", "a\x00b"):
            with self.subTest(title=repr(title)), self.assertRaises(ValueError):
                self.validate(title=title)
        self.validate(title="مراجعة إعدادات CI")


if __name__ == "__main__":
    unittest.main()
