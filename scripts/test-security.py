#!/usr/bin/env python3
"""Non-destructive regression tests for the Git safety barriers."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class SecurityChecks(unittest.TestCase):
    def setUp(self):
        base = "/tmp/opencode" if Path("/tmp/opencode").is_dir() else None
        self.temp = tempfile.TemporaryDirectory(prefix="vanish-git-tests-", dir=base)
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "user.name", "Fixture")
        shutil.copy(ROOT / ".gitignore", self.repo)
        (self.repo / "scripts").mkdir()
        (self.repo / ".githooks").mkdir()
        shutil.copy(ROOT / "scripts/security-audit.sh", self.repo / "scripts")
        shutil.copy(ROOT / ".githooks/pre-commit", self.repo / ".githooks")
        self.secret = "ghp_" + "A" * 36

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, check=True,
                              capture_output=True, text=True)

    def run_script(self, script):
        return subprocess.run(["bash", script], cwd=self.repo,
                              capture_output=True, text=True)

    def test_clean_index_and_history_pass(self):
        (self.repo / "fixture.txt").write_text("plain fixture")
        self.git("add", ".")
        hook = self.run_script(".githooks/pre-commit")
        self.assertEqual(hook.returncode, 0, hook.stdout + hook.stderr)
        self.git("commit", "-qm", "clean fixture")
        audit = self.run_script("scripts/security-audit.sh")
        self.assertEqual(audit.returncode, 0, audit.stdout + audit.stderr)

    def test_hook_ignores_unstaged_secret_but_audit_detects_it(self):
        fixture = self.repo / "fixture.txt"
        fixture.write_text("clean index")
        self.git("add", ".")
        fixture.write_text(self.secret)
        hook = self.run_script(".githooks/pre-commit")
        self.assertEqual(hook.returncode, 0, hook.stdout + hook.stderr)
        self.git("commit", "-qm", "clean indexed fixture")
        audit = self.run_script("scripts/security-audit.sh")
        self.assertNotEqual(audit.returncode, 0)
        self.assertIn("fixture.txt", audit.stdout)
        self.assertNotIn(self.secret, audit.stdout + audit.stderr)

    def test_hook_checks_index_not_worktree_and_redacts(self):
        fixture = self.repo / "fixture with space\nand newline.txt"
        fixture.write_text(self.secret)
        self.git("add", "--", fixture.name)
        fixture.write_text("clean working copy")
        result = self.run_script(".githooks/pre-commit")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(self.secret, result.stdout + result.stderr)

    def test_hook_rejects_nested_env(self):
        (self.repo / "nested").mkdir()
        (self.repo / "nested/.env").write_text("fixture")
        self.git("add", "-f", "nested/.env")
        self.assertNotEqual(self.run_script(".githooks/pre-commit").returncode, 0)

    def test_hook_excludes_exact_files_not_similar_prefixes(self):
        fixture = self.repo / ".gitignore.fixture.txt"
        fixture.write_text(self.secret)
        self.git("add", "--", fixture.name)
        result = self.run_script(".githooks/pre-commit")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(self.secret, result.stdout + result.stderr)

    def test_hook_checks_renamed_destination_class(self):
        (self.repo / "fixture.txt").write_text("fixture, not a real key")
        self.git("add", "fixture.txt")
        self.git("commit", "-qm", "fixture")
        self.git("mv", "fixture.txt", "fixture.key")
        self.assertNotEqual(self.run_script(".githooks/pre-commit").returncode, 0)

    def test_audit_detects_ignored_tracked_file(self):
        (self.repo / "fixture.key").write_text("fixture, not a real key")
        self.git("add", "-f", "fixture.key")
        self.git("commit", "-qm", "fixture")
        result = self.run_script("scripts/security-audit.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("fixture.key", result.stdout)

    def test_audit_checks_root_commit_and_redacts(self):
        fixture = self.repo / "fixture with space.txt"
        fixture.write_text(self.secret)
        self.git("add", "--", fixture.name)
        self.git("commit", "-qm", "root fixture")
        fixture.write_text("removed from working tree and tip")
        self.git("add", "--", fixture.name)
        self.git("commit", "-qm", "clean tip")
        result = self.run_script("scripts/security-audit.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("истории", result.stdout)
        self.assertNotIn(self.secret, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
