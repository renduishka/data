"""Перевірки облікового запису, точності PII та відсутності витоків у --mask."""

import contextlib
import io
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from labs.lab02.task1 import SESSION_TIMEOUT_SEC, Session, User, UserAccount
from labs.lab02.task2 import find_in_line, run_analysis, scan_directory

DATA = Path(__file__).resolve().parents[1] / "labs/lab02/data/data_v13/scan"


class AccountTests(unittest.TestCase):
    def setUp(self):
        self.user = User("tester", "tester@example.test")
        self.user.set_password("Test13!")
        self.account = UserAccount(self.user)

    def test_login_timeout_logout(self):
        self.assertFalse(self.account.login("tester", "bad", "192.0.2.1"))
        self.assertIsNone(self.account.session)
        self.assertTrue(self.account.login("tester", "Test13!", "192.0.2.1"))
        self.assertTrue(self.account.is_authenticated())
        self.account.session.last_activity -= timedelta(seconds=SESSION_TIMEOUT_SEC + 1)
        before = self.account.session.last_activity
        self.assertFalse(self.account.is_authenticated())
        self.assertEqual(before, self.account.session.last_activity)
        self.account.logout()
        self.assertIsNone(self.account.session)
        self.assertEqual(
            [r.action for r in self.account.audit_log.logs],
            ["login_failure", "login_success", "logout"],
        )

    def test_validation_and_keys(self):
        for email in (
            "ab@example.test",
            "1abc@example.test",
            "abc@localhost",
            "abc.def@example.test",
        ):
            with self.assertRaises(ValueError):
                self.user.email = email
        with self.assertRaises(TypeError):
            self.account["active"] = "yes"
        for key in ("password_hash", "_User__password_salt", "unknown"):
            with self.assertRaises(KeyError):
                self.account[key]
        self.assertNotIn("Test13!", str(self.user))
        self.user.deactivate()
        self.assertFalse(self.account.login("tester", "Test13!", "192.0.2.1"))
        with self.assertRaises(ValueError):
            Session("192.0.2.1").is_active(0)

    def test_replacing_user_invalidates_session(self):
        self.account.login("tester", "Test13!", "192.0.2.1")
        self.account["user"] = User("other", "other@example.test")
        self.assertFalse(self.account.is_authenticated())


class ScannerTests(unittest.TestCase):
    def test_fixture_counts_and_filters(self):
        result = scan_directory(DATA, mask=True)
        self.assertEqual(
            result["counts"], {"emails": 4, "cards": 3, "phones": 4, "ips": 4}
        )
        self.assertEqual(result["files_scanned"], 4)
        self.assertEqual(result["total_matches"], 15)
        self.assertEqual(scan_directory(DATA, "cards")["total_matches"], 3)
        self.assertEqual(scan_directory(DATA, "emails")["total_matches"], 4)

    def test_false_positives_and_overlap(self):
        self.assertEqual(
            list(find_in_line("2026-09-27 999.1.2.3 version=1.2.3", "all")), []
        )
        found = list(find_in_line("4000000000000002 4111-1111-1111-1111", "all"))
        self.assertEqual([f[0] for f in found], ["cards", "cards"])
        self.assertEqual(
            len(list(find_in_line("0501234567 +380 67 123 45 67", "all"))), 2
        )

    def test_masked_outputs_do_not_contain_raw_values(self):
        raw = scan_directory(DATA)
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "result.json"
            console = io.StringIO()
            with (
                contextlib.redirect_stdout(console),
                contextlib.redirect_stderr(console),
            ):
                self.assertEqual(run_analysis(DATA, "all", True, output), 0)
            combined = output.read_text() + console.getvalue()
            for item in raw["findings"]:
                self.assertNotIn(item["value"], combined)
            self.assertTrue(json.loads(output.read_text())["masked"])

    def test_unreadable_binary_symlink_and_missing_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "binary.bin").write_bytes(b"\xff\x00")
            (root / "ok.txt").write_text("No data")
            (root / "link.txt").symlink_to(DATA / "notes/users.txt")
            result = scan_directory(root)
            self.assertEqual(result["files_scanned"], 1)
            self.assertEqual(result["files_skipped"], 2)
            with self.assertRaises(ValueError):
                scan_directory(root / "missing")

    def test_output_cannot_overwrite_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.txt"
            source.write_text("alice@example.test")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(run_analysis(root, "all", True, source), 1)
            self.assertEqual(source.read_text(), "alice@example.test")


if __name__ == "__main__":
    unittest.main()
