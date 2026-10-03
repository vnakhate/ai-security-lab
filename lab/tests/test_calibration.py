import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run_calibration as c


class CalibrationTests(unittest.TestCase):
    def reports(self, repeats=3):
        return [{'profile': profile, 'complete': True, 'model_audit_counts_match': True,
                 'outcomes': {case: 'observed_control_pass' for case in c.AI_IDS}}
                for _ in range(repeats) for profile in ('fixed', 'vulnerable')]

    def test_completed_transport_does_not_accept_model(self):
        result = c.aggregate(self.reports(), 3)
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(result['security_acceptance'], 'pending independent human review')
        self.assertEqual(result['manual_vs_ai_value'], 'not measured')

    def test_incomplete_inconclusive_unstable_and_missing_logs_fail(self):
        for change in ('missing_run', 'inconclusive', 'unstable', 'missing_logs'):
            with self.subTest(change=change):
                reports = self.reports()
                if change == 'missing_run': reports.pop()
                elif change == 'missing_logs': reports[0]['model_audit_counts_match'] = False
                else: reports[0]['outcomes'][c.AI_IDS[0]] = 'inconclusive' if change == 'inconclusive' else 'reproduced_failure'
                self.assertEqual(c.aggregate(reports, 3)['exit_code'], 2)

    def test_consistent_fixed_failure_is_failure_but_vulnerable_is_observation(self):
        reports = self.reports()
        for r in reports:
            r['outcomes'][c.AI_IDS[0]] = 'reproduced_failure'
        self.assertEqual(c.aggregate(reports, 3)['exit_code'], 1)
        for r in reports:
            if r['profile'] == 'fixed': r['outcomes'][c.AI_IDS[0]] = 'observed_control_pass'
        self.assertEqual(c.aggregate(reports, 3)['exit_code'], 0)

    def test_prepare_never_starts_targets(self):
        with tempfile.TemporaryDirectory() as root, patch.object(c, 'run_profile') as execute:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(c.main(['--prepare', '--output-root', root]), 0)
            execute.assert_not_called()
            directory = next(Path(root).glob('calibration-*'))
            self.assertTrue((directory / 'plan.json').exists())
            self.assertFalse((directory / 'calibration.json').exists())

    def test_external_endpoint_is_rejected_before_execution(self):
        with patch.object(c, 'run_profile') as execute:
            with self.assertRaises(c.h.Denied):
                c.main(['--model-url', 'http://192.0.2.1:1234/v1/chat/completions', '--model', 'test'])
            execute.assert_not_called()
