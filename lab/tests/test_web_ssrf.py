"""U4: web SSRF verified at the out-of-band sink, not by self-report."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from application_server import Application
from oob_sink import Sink


class WebSsrfTests(unittest.TestCase):
    def test_fetch_reaches_oob_sink_only_in_vulnerable(self):
        for profile, hits in (('fixed', 0), ('vulnerable', 1)):
            with self.subTest(profile=profile), Sink() as sink, \
                    tempfile.TemporaryDirectory() as directory:
                app = Application(Path(directory) / 'app', profile)
                try:
                    token = 'case-ssrf-01'
                    status, result = app.handle('/api/fetch', {'url': sink.url(token)},
                                                app.sessions['alice'])
                    self.assertEqual(status, 200)
                    self.assertEqual(result.get('fetched'), profile == 'vulnerable')
                    # Ground truth is the sink hit, independent of the response body.
                    self.assertEqual(len(sink.received(token)), hits)
                finally:
                    app.db.close()


if __name__ == '__main__':
    unittest.main()
