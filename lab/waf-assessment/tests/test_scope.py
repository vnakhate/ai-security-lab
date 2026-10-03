import contextlib
import datetime as dt
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import scope
import waf_check
import run_assessment
from scope_helpers import make_scope

class ScopeTests(unittest.TestCase):
    def test_missing_scope_or_target_sends_nothing(self):
        with patch('waf_check.subprocess.run') as collect,contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(waf_check.main(['https://example.invalid/']),2)
            self.assertEqual(run_assessment.main(['https://example.invalid/']),2)
            with self.assertRaises(SystemExit):run_assessment.main([])
            collect.assert_not_called()

    def test_changed_expired_and_invalid_scopes_denied(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'scope.json';url='https://example.invalid/api/search'
            for changes in ({'target_url':'https://other.invalid/'},{'parameter':'q'}, {'method':'POST'},
                            {'expires_utc':(scope.now()-dt.timedelta(seconds=1)).isoformat()},
                            {'code_sha256':'changed'},{'probes':['sqli']},{'probes':['control','unknown']},
                            {'limits':{'requests':6,'seconds':180,'interval_seconds':2}}):
                make_scope(path,**changes)
                with self.subTest(changes=changes),self.assertRaises(scope.ScopeError):scope.validate(path,url,'test',1)
                with patch('waf_check.subprocess.run') as send,contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(waf_check.main([url,'--scope',str(path)]),2);send.assert_not_called()

    def test_expiry_time_and_request_limits_before_next_request(self):
        with tempfile.TemporaryDirectory() as d:
            record=make_scope(Path(d)/'scope.json',probes=['control'],limits={'requests':1,'seconds':1,'interval_seconds':1})
            campaign=scope.Campaign(record);campaign.reserve()
            with self.assertRaisesRegex(scope.ScopeError,'request budget'):campaign.reserve()
            campaign=scope.Campaign(record);campaign.started-=2
            with self.assertRaisesRegex(scope.ScopeError,'time budget'):campaign.reserve()
            campaign=scope.Campaign(record)
            record['expires_utc']=(scope.now()-dt.timedelta(seconds=1)).isoformat()
            with self.assertRaisesRegex(scope.ScopeError,'expired'):campaign.reserve()
