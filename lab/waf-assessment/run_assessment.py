#!/usr/bin/env python3
"""Validate the package, collect paced observations and summarize the evidence."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import waf_check
from scope import validate as validate_scope

PACKAGE = Path(__file__).resolve().parent


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('url', nargs='?', help='Explicit approved endpoint; required for collection')
    parser.add_argument('--scope', type=Path, help='Approved campaign scope; required for collection')
    parser.add_argument('--param', default='test')
    parser.add_argument('--interval', type=float, default=10,
                        help='Seconds between requests (default: 10; minimum: 1)')
    parser.add_argument('--output-root', type=Path, default=PACKAGE / 'runs',
                        help='Parent folder for a unique run directory')
    parser.add_argument('--check-only', action='store_true',
                        help='Run offline validation without target requests')
    args = parser.parse_args(argv)
    # Reject invalid configuration before creating artifacts or sending requests.
    if not args.check_only and not args.url:parser.error('Collection requires an explicit target URL and --scope')
    waf_check.parse_args([args.url or 'https://offline.invalid/', args.param, '--interval', str(args.interval)])
    approved=None
    if not args.check_only:
        try:approved=validate_scope(args.scope,args.url,args.param,args.interval)
        except (ValueError,KeyError,TypeError,OSError) as exc:
            print('Collection denied: '+str(exc),file=sys.stderr)
            return 2
    missing = [name for name in ('curl', 'bash') if shutil.which(name) is None]
    if missing:
        print('Missing dependencies: ' + ', '.join(missing), file=sys.stderr)
        return 2
    try:
        args.output_root.mkdir(parents=True, exist_ok=True)
        stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        run = Path(tempfile.mkdtemp(prefix=f'assessment-{stamp}-', dir=args.output_root)).resolve()
    except OSError as exc:
        print(f'Cannot create run directory: {exc}', file=sys.stderr)
        return 2
    report = {'started_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
              'target': args.url, 'parameter': args.param,
              'interval_seconds': args.interval, 'concurrency': 1,
              'maximum_requests': approved['limits']['requests'] if approved else 0, 'check_only': args.check_only,
              'python_version': sys.version, 'run_directory': str(run),
              'authorization': approved if approved else 'offline validation only',
              'validation': 'pending', 'collection': 'not_started'}

    def save(code):
        report['exit_code'] = code
        report['finished_utc'] = dt.datetime.now(dt.timezone.utc).isoformat()
        (run / 'launcher-summary.json').write_text(json.dumps(report, indent=2) + '\n')
        print(f'\nRun directory: {run}')
        print(f'Launcher summary: {run / "launcher-summary.json"}')
        return code

    print(f'Target: {args.url}\nInterval: {args.interval:g}s; sequential requests\nRun directory: {run}')
    print('\nChecking shell syntax and running offline tests...')
    checks = [
        ['bash', '-n', str(PACKAGE / 'akamai-waf-check.sh')],
        ['bash', '-n', str(PACKAGE / 'run-waf-assessment.sh')],
        [sys.executable, '-m', 'unittest', 'discover', '-s', str(PACKAGE / 'tests'), '-v'],
    ]
    try:
        with (run / 'validation.log').open('w') as log:
            for command in checks:
                result = subprocess.run(command, cwd=PACKAGE, capture_output=True, text=True,
                                        timeout=60, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
                output = result.stdout + result.stderr
                log.write(output)
                print(output, end='', flush=True)
                if result.returncode:
                    report['validation'] = 'failed'
                    print('Validation failed; no target requests were sent.')
                    return save(2)
    except (OSError, subprocess.TimeoutExpired) as exc:
        report['validation'] = 'failed'
        report['error'] = str(exc)
        print(f'Validation failed: {exc}. No target requests were sent.')
        return save(2)
    except KeyboardInterrupt:
        report['validation'] = 'interrupted'
        return save(130)
    report['validation'] = 'passed'
    if args.check_only:
        print('Offline checks passed. No target requests were sent.')
        return save(0)

    print('\nStarting paced collection. Ctrl+C stops the run.')
    try:
        code = waf_check.main([args.url, args.param, '--interval', str(args.interval),
                               '--output', str(run / 'evidence'), '--scope', str(args.scope)])
    except KeyboardInterrupt:
        report['collection'] = 'interrupted'
        print('\nInterrupted. Partial evidence is retained; this run is incomplete.')
        return save(130)
    except Exception as exc:
        report['collection'] = 'failed'
        report['error'] = str(exc)
        print(f'Collection failed: {exc}. Partial evidence is retained.')
        return save(1)
    evidence = run / 'evidence' / 'results.json'
    if evidence.exists():
        collected = json.loads(evidence.read_text())
        report['collection'] = 'completed' if collected['complete'] else 'incomplete'
        report['results_file'] = str(evidence)
        print('\nObservations:')
        for observation in collected['observations']:
            print(f"  {observation['label']:12} HTTP {observation['status']:03} {observation['verdict']}")
        if collected['stop_reason']:
            print(collected['stop_reason'])
        if collected['observations'] and collected['observations'][0]['status'] in (403, 406):
            print('The benign baseline was denied. Inspect edge/application logs before resuming; do not bypass the denial.')
    else:
        report['collection'] = 'failed'
    print('Completion means evidence collection finished, not that the target is secure.')
    return save(code)


if __name__ == '__main__':
    sys.exit(main())
