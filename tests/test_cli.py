import contextlib
import io
import unittest
from sudetect.__main__ import main


class CommandTests(unittest.TestCase):
    def test_github_discovery_command_dispatches_without_network(self):
        from unittest.mock import patch
        with patch('sudetect.github_discovery.main', return_value=0) as command:
            self.assertEqual(main(['github-discover', '--scope-id', 'fixture-team']), 0)
        command.assert_called_once_with(['--scope-id', 'fixture-team'])

    def test_help_and_version_no_optional_import(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(['--help']), 0)
            self.assertEqual(main(['--version']), 0)
        self.assertIn('2.0.0', out.getvalue())

    def test_unknown_command_safe(self):
        out = io.StringIO()
        with contextlib.redirect_stderr(out):
            self.assertEqual(main(['https://secret.example/?token=SECRET']), 2)
        self.assertEqual(out.getvalue().strip(), 'unknown_command')

    def test_scope_required_no_network(self):
        import os
        from unittest.mock import patch
        out = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stderr(out):
            self.assertEqual(main(['probe', 'https://app.example/']), 2)
        self.assertIn('scope', out.getvalue())


if __name__ == '__main__':
    unittest.main()
