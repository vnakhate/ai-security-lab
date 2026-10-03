import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run_assessment
from scope_helpers import make_scope


class LauncherTests(unittest.TestCase):
    def run_launcher(self, check_only=False, validation_code=0, collection_code=0):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        scope_path=root/'scope.json';make_scope(scope_path,interval=10)
        args = ['--output-root', str(root)] + (['--check-only'] if check_only else
                ['https://example.invalid/api/search','--scope',str(scope_path)])

        def collect(argv):
            out = Path(argv[argv.index('--output') + 1])
            out.mkdir()
            (out / 'results.json').write_text(json.dumps({
                'complete': collection_code == 0,
                'stop_reason': None if collection_code == 0 else 'blocked baseline',
                'observations': [{'label': 'control', 'status': 403 if collection_code else 200,
                                  'verdict': 'suspected_block' if collection_code else 'inconclusive'}]}))
            return collection_code

        with patch('run_assessment.shutil.which', return_value='/mock/tool'), \
             patch('run_assessment.subprocess.run', return_value=subprocess.CompletedProcess([], validation_code, 'checks', '')), \
             patch('run_assessment.waf_check.main', side_effect=collect) as collector, \
             contextlib.redirect_stdout(io.StringIO()):
            code = run_assessment.main(args)
        report = json.loads(next(root.glob('*/launcher-summary.json')).read_text())
        return code, report, collector.call_count

    def test_check_only_never_collects(self):
        code, report, calls = self.run_launcher(check_only=True)
        self.assertEqual((code, calls), (0, 0))
        self.assertEqual(report['validation'], 'passed')

    def test_validation_failure_never_collects(self):
        code, report, calls = self.run_launcher(validation_code=1)
        self.assertEqual((code, calls), (2, 0))
        self.assertEqual(report['validation'], 'failed')

    def test_collector_failure_exit_is_preserved(self):
        code, report, calls = self.run_launcher(collection_code=1)
        self.assertEqual((code, calls), (1, 1))
        self.assertEqual(report['collection'], 'incomplete')

    def test_completed_collection(self):
        code, report, calls = self.run_launcher()
        self.assertEqual((code, calls), (0, 1))
        self.assertEqual(report['collection'], 'completed')


if __name__ == '__main__':
    unittest.main()
