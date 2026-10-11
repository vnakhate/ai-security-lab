"""U4: mass-assignment (BOPLA) and broken-auth (alg=none) cases against the range."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import harness as h
from application_server import Application
from catalog import BY_ID, jwt


class WebBoplaAuthTests(unittest.TestCase):
    def _app(self, profile, directory):
        return Application(Path(directory) / 'app', profile)

    def test_mass_assignment_escalates_only_in_vulnerable(self):
        case = BY_ID['web-mass-assignment']
        for profile, escalates in (('fixed', False), ('vulnerable', True)):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as directory:
                app = self._app(profile, directory)
                try:
                    token = app.sessions['alice']
                    _, control = app.handle('/api/records/update', {'value': 'note'}, token)
                    _, attack = app.handle('/api/records/update', {'value': 'note', 'tier': 'admin'}, token)
                    self.assertEqual(control['tier'], 'user')
                    self.assertEqual(attack['tier'] == 'admin', escalates)
                    self.assertIs(h.score(case, {'status': 200, 'body': attack}), escalates)
                    self.assertTrue(h.control_valid(case, {'status': 200, 'body': control}))
                finally:
                    app.db.close()

    def test_alg_none_token_trusted_only_in_vulnerable(self):
        case = BY_ID['web-auth-token']
        for profile, impersonates in (('fixed', False), ('vulnerable', True)):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as directory:
                app = self._app(profile, directory)
                try:
                    token = app.sessions['alice']
                    _, control = app.handle('/api/link', {'id_token': jwt('HS256', 'admin')}, token)
                    _, attack = app.handle('/api/link', {'id_token': jwt('none', 'admin')}, token)
                    self.assertEqual(control['linked_as'], 'alice')
                    self.assertEqual(attack['linked_as'] == 'admin', impersonates)
                    self.assertIs(h.score(case, {'status': 200, 'body': attack}), impersonates)
                    self.assertTrue(h.control_valid(case, {'status': 200, 'body': control}))
                finally:
                    app.db.close()


if __name__ == '__main__':
    unittest.main()
