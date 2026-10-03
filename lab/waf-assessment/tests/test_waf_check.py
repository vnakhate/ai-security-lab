"""Offline integration checks: a fake curl replaces all network requests."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import waf_check
from scope_helpers import make_scope

MOCK_CURL = '''#!/usr/bin/env python3
import os, sys, json
from pathlib import Path
args = sys.argv[1:]
url = args[args.index('--url') + 1]
control = 'test=hello' in url
code = '200' if control else os.environ.get('FAKE_STATUS', '200')
body = os.environ.get('FAKE_BODY', 'Normal page')
if os.environ.get('FAKE_BASELINE'):
    code = os.environ['FAKE_BASELINE']
Path(args[args.index('--dump-header') + 1]).write_text('HTTP/1.1 '+code+' OK\\nContent-Type: text/html; charset=utf-8\\nSet-Cookie: a=1\\nSet-Cookie: b=2\\n')
Path(args[args.index('--output') + 1]).write_text(body)
Path(args[args.index('--trace-ascii') + 1]).write_text('mock request/response trace')
print(code+'\\n0.01\\n'+str(len(body)))
print(json.dumps({'http_code':int(code),'time_total':0.01,'size_download':len(body),'time_namelookup':0.001,'remote_ip':'192.0.2.1','http_version':'2'}))
if os.environ.get('FAKE_FAILURE'):
    sys.stderr.write('mock connection failure')
    sys.exit(7)
'''


class CollectorTests(unittest.TestCase):
    def run_case(self, **env):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        fake = root / 'curl'
        fake.write_text(MOCK_CURL)
        fake.chmod(0o755)
        evidence = root / 'evidence'
        scope_path=root/'scope.json'
        probes=env.pop('SCOPE_PROBES',None)
        make_scope(scope_path,**({'probes':probes.split(',')} if probes else {}))
        with patch.dict(os.environ, dict(env, PATH=str(root)), clear=True), \
                patch('waf_check.time.sleep'), contextlib.redirect_stdout(io.StringIO()):
            # Absolute interpreter avoids relying on PATH in fake curl's shebang.
            fake.write_text(MOCK_CURL.replace('/usr/bin/env python3', sys.executable))
            exit_code = waf_check.main(['https://example.invalid/api/search', '--output', str(evidence), '--scope',str(scope_path)])
        return exit_code, json.loads((evidence / 'results.json').read_text()), evidence

    def test_benign_vendor_and_reference_text(self):
        code, report, _ = self.run_case(FAKE_BODY='Akamai documentation reference guide')
        self.assertEqual(code, 0)
        self.assertTrue(report['complete'])
        self.assertTrue(all(r['verdict'] == 'inconclusive' for r in report['observations']))

    def test_only_approved_probes_execute_and_exclusions_remain_visible(self):
        code,report,_=self.run_case(SCOPE_PROBES='control,xss')
        self.assertEqual(code,0)
        self.assertEqual([r['label'] for r in report['observations']],['control','xss'])
        self.assertEqual(report['planned_probes'],['control','xss'])
        self.assertIn('sqli',report['untested_probes'])

    def test_app_403_not_attributed_to_edge(self):
        code, report, _ = self.run_case(FAKE_STATUS='403', FAKE_BODY='Application permission failure')
        self.assertEqual(code, 0)
        self.assertEqual(report['observations'][1]['verdict'], 'suspected_block')

    def test_reflection_is_not_app_proof(self):
        _, report, _ = self.run_case(FAKE_BODY='Plain text alert(1)')
        self.assertTrue(all(r['verdict'] == 'inconclusive' for r in report['observations']))

    def test_failure_stops_and_returns_nonzero(self):
        code, report, root = self.run_case(FAKE_FAILURE='1')
        self.assertEqual(code, 1)
        self.assertFalse(report['complete'])
        self.assertEqual(len(report['observations']), 1)
        self.assertEqual(report['observations'][0]['curl_exit_code'], 7)
        self.assertIn('mock connection failure', (root / '00-control/curl-stderr.txt').read_text())

    def test_rate_limit_and_server_error_stop(self):
        for status in ('429', '503'):
            with self.subTest(status=status):
                code, report, _ = self.run_case(FAKE_STATUS=status)
                self.assertEqual(code, 1)
                self.assertEqual(len(report['observations']), 2)

    def test_process_timeout_is_incomplete(self):
        with patch('waf_check.subprocess.run', side_effect=subprocess.TimeoutExpired('curl', 20)):
            code, report, _ = self.run_case()
        self.assertEqual(code, 1)
        self.assertFalse(report['complete'])
        self.assertEqual(report['observations'][0]['curl_exit_code'], 124)

    def test_redirecting_or_blocked_control_stops(self):
        for status in ('302', '401', '403', '404'):
            with self.subTest(status=status):
                code, report, _ = self.run_case(FAKE_BASELINE=status)
                self.assertEqual(code, 1)
                self.assertEqual(len(report['observations']), 1)

    def test_exact_path_evidence_and_curl_constraints(self):
        _, report, root = self.run_case()
        self.assertEqual(len(report['observations']), 6)
        req = json.loads((root / '02-xss/request.json').read_text())
        self.assertTrue(req['url'].startswith('https://example.invalid/api/search?'))
        self.assertIn('%3Cscript%3E', req['url'])
        self.assertEqual(req['curl_argv'][1], '-q')
        self.assertNotIn('-L', req['curl_argv'])
        self.assertIn('--max-time', req['curl_argv'])
        self.assertTrue((root / '02-xss/response-headers.txt').exists())
        self.assertTrue((root / '02-xss/response-body.bin').exists())
        self.assertEqual((root / 'results.json').stat().st_mode & 0o077, 0)

    def test_bad_input_rejected(self):
        for url in ('file:///tmp/example', 'https://u:p@example.invalid',
                    'https://example.invalid/?x=1', 'https://example.invalid/#x',
                    'https://example.invalid/has space', 'https://example.invalid:bad'):
            with self.subTest(url=url), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as exc:
                    waf_check.parse_args([url])
                self.assertEqual(exc.exception.code, 2)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            waf_check.parse_args(['https://example.invalid', 'x&extra=1'])

    def test_detailed_analysis_preserves_response_and_duplicate_headers(self):
        _, report, root = self.run_case(FAKE_BODY='Reference&#32;&#35;18.test.123')
        detailed = json.loads((root / 'analysis.json').read_text())
        response = detailed['observations'][0]['response']
        self.assertEqual(response['reference_numbers'], ['18.test.123'])
        self.assertEqual(response['curl_metrics']['remote_ip'], '192.0.2.1')
        cookies = [h['value'] for h in response['headers'] if h['name'] == 'Set-Cookie']
        self.assertEqual(cookies, ['a=1', 'b=2'])
        self.assertEqual(response['body_text'], 'Reference&#32;&#35;18.test.123')
        self.assertTrue((root / '00-control/curl-trace.txt').exists())
        self.assertTrue((root / 'analysis-report.md').exists())
        self.assertTrue((root / 'sha256-manifest.json').exists())

    def test_failed_run_has_analysis_and_untested_coverage(self):
        _, report, root = self.run_case(FAKE_FAILURE='1')
        detailed = json.loads((root / 'analysis.json').read_text())
        self.assertFalse(detailed['complete'])
        self.assertEqual(len(detailed['untested_probes']), 5)
        self.assertFalse(detailed['observations'][0]['response']['transfer_completed'])
        self.assertIn('mock connection failure', detailed['observations'][0]['curl_error'])


if __name__ == '__main__':
    os.umask(0o077)
    unittest.main()
