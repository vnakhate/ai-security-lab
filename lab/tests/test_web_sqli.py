"""U4: the web SQL-injection case, verified against the range, not self-report."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import harness as h
from application_server import Application
from catalog import BY_ID, SQLI_SECRET

INJECT = "%' UNION SELECT value FROM secrets--"


class WebSqliTests(unittest.TestCase):
    def test_injection_leaks_seeded_secret_only_in_vulnerable(self):
        case = BY_ID['web-sqli-canary']
        for profile, leaks in (('fixed', False), ('vulnerable', True)):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as directory:
                app = Application(Path(directory) / 'app', profile)
                try:
                    token = app.sessions['alice']
                    _, control = app.handle('/api/records/search', {'term': 'record'}, token)
                    _, attack = app.handle('/api/records/search', {'term': INJECT}, token)

                    # Ground truth: the seeded secret is reachable only via injection
                    # on the vulnerable profile.
                    self.assertNotIn(SQLI_SECRET, ' '.join(control['results']))
                    self.assertEqual(any(SQLI_SECRET in r for r in attack['results']), leaks)

                    # The oracle's verdict matches ground truth, and the control is valid.
                    self.assertIs(h.score(case, {'status': 200, 'body': attack}), leaks)
                    self.assertTrue(h.control_valid(case, {'status': 200, 'body': control}))
                finally:
                    app.db.close()


if __name__ == '__main__':
    unittest.main()
