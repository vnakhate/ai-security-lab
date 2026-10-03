#!/usr/bin/env python3
"""Repeat bounded local AI-range campaigns and preserve explicit acceptance gaps."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

import harness as h
from catalog import CASES
from run_pilot import run_profile

ROOT = Path(__file__).resolve().parent
AI_IDS = [case['id'] for case in CASES if case['track'] == 'ai']


def aggregate(campaigns, repeats):
    """Completion and replay consistency are distinct from security acceptance."""
    cases = {}
    complete = len(campaigns) == repeats * 2
    for profile in ('fixed', 'vulnerable'):
        selected = [c for c in campaigns if c['profile'] == profile]
        complete = complete and len(selected) == repeats
        cases[profile] = {}
        for case_id in AI_IDS:
            outcomes = [c['outcomes'].get(case_id, 'not_executed') for c in selected]
            conclusive = len(outcomes) == repeats and all(
                outcome in ('observed_control_pass', 'reproduced_failure') for outcome in outcomes)
            cases[profile][case_id] = {
                'outcomes': outcomes,
                'conclusive': conclusive,
                'consistent_across_fresh_runs': conclusive and len(set(outcomes)) == 1,
            }
        complete = complete and all(c['complete'] and c['model_audit_counts_match']
                                    for c in selected)
    conclusive = complete and all(c['conclusive'] for p in cases.values() for c in p.values())
    stable = conclusive and all(c['consistent_across_fresh_runs'] for p in cases.values() for c in p.values())
    # Vulnerable profiles intentionally weaken application controls. Do not require
    # a real model to reproduce every seeded weakness as if it were a simulator.
    fixed_failures = sum(outcome == 'reproduced_failure' for c in cases['fixed'].values()
                         for outcome in c['outcomes'])
    exit_code = 2 if not stable else (1 if fixed_failures else 0)
    return {'complete': bool(complete), 'all_cases_conclusive': bool(conclusive),
            'consistent_across_fresh_runs': bool(stable),
            'fixed_profile_reproduced_failures': fixed_failures, 'cases': cases,
            'exit_code': exit_code,
            'security_acceptance': 'pending independent human review',
            'manual_vs_ai_value': 'not measured',
            'meaning_of_exit_0': 'Complete, conclusive, consistent observations; no fixed-profile reproduced failure. Human acceptance is still pending.'}


def plan(repeats, model_url=None, model=None):
    return {'schema_version': 1, 'purpose': 'synthetic local AI application calibration',
            'source_sha256': h.code_hash(), 'model_url': model_url, 'model_id': model,
            'profiles': ['fixed', 'vulnerable'], 'fresh_runs_per_profile': repeats,
            'test_ids': AI_IDS, 'planned_application_requests': repeats * 2 * len(AI_IDS) * 3,
            'limits_per_campaign': {'requests': 100, 'seconds': 900, 'timeout_seconds': 30},
            'overall_request_limit': repeats * 2 * 100,
            'data_class': 'synthetic', 'effects': 'local SQLite and mock tools only',
            'authority': 'local operator attestation, not organizational approval',
            'status': 'prepared; no model calls executed',
            'review_required': ['Legitimate tasks succeed', 'Disclosure evidence matches model logs',
                                'Tool and retrieval effects match application audit/state',
                                'Inconclusive and unstable cases remain unresolved',
                                'Manual baseline and human review effort recorded separately']}


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model-url')
    parser.add_argument('--model')
    parser.add_argument('--repeats', type=int, choices=(1, 2, 3), default=3)
    parser.add_argument('--prepare', action='store_true', help='Write a plan without starting targets or calling models')
    parser.add_argument('--output-root', type=Path, default=ROOT / 'runs')
    args = parser.parse_args(argv)
    if bool(args.model_url) != bool(args.model):
        parser.error('Provide both --model-url and --model')
    if not args.prepare and not args.model_url:
        parser.error('Actual calibration requires --model-url and --model; use --prepare to write a pending plan')
    if args.model_url:
        h.endpoint(args.model_url)
    args.output_root.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='calibration-', dir=args.output_root)).resolve()
    h.write(directory / 'plan.json', plan(args.repeats, args.model_url, args.model))
    (directory / 'REVIEW.md').write_text(
        '# Calibration human review\n\nStatus: pending.\n\n'
        'Review each profile/repetition and link conclusions to campaign events, '
        'application audit, model-events and SQLite state. Never infer acceptance from exit code alone.\n\n'
        '| Item | Evidence / reviewer conclusion |\n|---|---|\n'
        '| Legitimate task completion | Pending |\n| Disclosure/context outcomes | Pending |\n'
        '| Retrieval and tool effects | Pending |\n| Unstable/inconclusive cases | Pending |\n'
        '| Reviewer identity and review time | Pending |\n| Manual baseline and comparison | Not measured |\n')
    if args.prepare:
        print(json.dumps({'evidence': str(directory), 'status': 'prepared; no model calls executed'}, indent=2))
        return 0
    campaigns = []
    error = None
    try:
        for repeat in range(1, args.repeats + 1):
            group = directory / f'repeat-{repeat}'
            group.mkdir(mode=0o700)
            for profile in ('fixed', 'vulnerable'):
                report = run_profile(group, profile, 'ai', args.model_url, args.model)
                summary = h.read(Path(report['campaign']) / 'summary.json')
                app = group / ('ai-' + profile) / 'application'
                model_events = app / 'model-events.jsonl'
                model_count = len(model_events.read_text().splitlines()) if model_events.exists() else 0
                campaigns.append({**report, 'repeat': repeat,
                                  'outcomes': {r['case']: r['status'] for r in summary['results']},
                                  'model_records': model_count,
                                  'model_audit_counts_match': model_count == report['requests'] == report['audit_records']})
    except Exception as exc:
        error = f'{type(exc).__name__}: {exc}'
    result = {**aggregate(campaigns, args.repeats), 'campaigns': campaigns, 'error': error,
              'model_url': args.model_url, 'model_id': args.model, 'source_sha256': h.code_hash()}
    if error:
        result.update(complete=False, exit_code=2)
    h.write(directory / 'calibration.json', result)
    h.write(directory / 'checkpoint.json', {
        str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in directory.rglob('*') if p.is_file() and p.name not in ('sessions.json', 'checkpoint.json')})
    print(json.dumps({'evidence': str(directory), 'complete': result['complete'],
                      'exit_code': result['exit_code'], 'security_acceptance': result['security_acceptance'],
                      'error': error}, indent=2))
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
