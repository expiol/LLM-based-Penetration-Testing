"""Tests for the in-process solver code lint pre-check."""

from __future__ import annotations

import unittest

from killchain_docker.agents.solver.lint import (
    SolverLintResult,
    lint_solver_code,
)


class SolverLintBasicTests(unittest.TestCase):
    def test_empty_string_rejected(self):
        result = lint_solver_code("", "python")
        self.assertFalse(result.ok)
        self.assertEqual(result.error_kind, "empty")

    def test_whitespace_only_rejected(self):
        result = lint_solver_code("   \n\t\n  ", "python")
        self.assertFalse(result.ok)
        self.assertEqual(result.error_kind, "empty")

    def test_valid_script_passes(self):
        code = (
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "import os\n"
            "import subprocess\n"
            "\n"
            "def main():\n"
            "    os.chdir('/tmp')\n"
            "    res = subprocess.run(['ls'], capture_output=True, text=True)\n"
            "    print(res.stdout)\n"
            "    sys.exit(0)\n"
            "\n"
            "if __name__ == '__main__':\n"
            "    main()\n"
        )
        result = lint_solver_code(code, "python")
        self.assertTrue(result.ok, msg=f"unexpected lint failure: {result.error_message}")

    def test_non_python_skips_ast_check(self):
        # Bash with sketchy syntax: still skipped because we don't lint bash.
        result = lint_solver_code("ls /tmp; ls -lah", "bash")
        self.assertTrue(result.ok)


class SolverLintSyntaxTests(unittest.TestCase):
    def test_unterminated_string_literal(self):
        # Mirrors the actual stfu run-c4d6ba61f9 attempt-2 fingerprint:
        # ``[*] Changed to {WORKDIR}")`` injected at line 1.
        code = '[*] Changed to {WORKDIR}")\nprint(1)\n'
        result = lint_solver_code(code, "python")
        self.assertFalse(result.ok)
        self.assertEqual(result.error_kind, "syntax")
        self.assertIsNotNone(result.offending_lineno)
        # Python 3.10+ reports "unterminated string literal"; older versions
        # report a generic "invalid syntax".  Either is fine — we just want
        # the error to mention something non-empty.
        self.assertTrue(result.error_message)

    def test_unbalanced_paren_reports_lineno(self):
        code = "import sys\nprint('hi'\n"
        result = lint_solver_code(code, "python")
        self.assertFalse(result.ok)
        self.assertEqual(result.error_kind, "syntax")
        self.assertIsNotNone(result.offending_lineno)


class SolverLintMissingImportTests(unittest.TestCase):
    def test_missing_sys_caught(self):
        # Mirrors the actual cycle-4 run-e61619246d fingerprint:
        # ``NameError: name 'sys' is not defined at line 70``.
        code = (
            "def main():\n"
            "    print('hi', file=sys.stderr)\n"
            "    sys.exit(0)\n"
            "\n"
            "main()\n"
        )
        result = lint_solver_code(code, "python")
        self.assertFalse(result.ok)
        self.assertEqual(result.error_kind, "missing_import")
        self.assertIn("sys", result.error_message)
        self.assertEqual(result.offending_lineno, 2)

    def test_missing_subprocess_caught(self):
        code = "import sys\nres = subprocess.run(['ls'])\nsys.exit(0)\n"
        result = lint_solver_code(code, "python")
        self.assertFalse(result.ok)
        self.assertEqual(result.error_kind, "missing_import")
        self.assertIn("subprocess", result.error_message)

    def test_aliased_import_does_not_false_positive(self):
        code = "import sys as _sys\n_sys.exit(0)\n"
        result = lint_solver_code(code, "python")
        self.assertTrue(result.ok)

    def test_from_import_does_not_false_positive(self):
        # ``from os import path`` makes ``path`` available; using ``path.join``
        # later must not be flagged as missing-import on `os`.
        code = "from os import path\nprint(path.join('/tmp', 'x'))\n"
        result = lint_solver_code(code, "python")
        self.assertTrue(result.ok)

    def test_local_attribute_access_not_flagged(self):
        code = (
            "class Foo:\n"
            "    def __init__(self):\n"
            "        self.value = 42\n"
            "foo = Foo()\n"
            "print(foo.value)\n"
        )
        result = lint_solver_code(code, "python")
        self.assertTrue(result.ok)


class SolverLintFingerprintTests(unittest.TestCase):
    def test_fingerprint_is_empty_when_ok(self):
        self.assertEqual(SolverLintResult.success().fingerprint(), "")

    def test_fingerprint_includes_lineno_when_known(self):
        result = lint_solver_code("print(\nprint(\n", "python")
        fp = result.fingerprint()
        self.assertIn("syntax", fp)
        self.assertIn("line", fp)


if __name__ == "__main__":
    unittest.main()
