#!/usr/bin/env python3
"""Run authenticated local-range campaigns and verify effects from SQLite state."""
import argparse
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import selectors
import sqlite3
import subprocess
import sys
import tempfile
import time
import harness as h
from catalog import CASES

ROOT=Path(__file__).resolve().parent

def run_profile(root,profile,track,model_url=None,model=None):
    directory=root/(track+'-'+profile);directory.mkdir(mode=0o700)
    state=directory/'application'
    cmd=[sys.executable,str(ROOT/'application_server.py'),'--directory',str(state),'--profile',profile,'--port','0']
    if model_url:cmd+=['--model-url',model_url,'--model',model]
    process=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'))
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout,selectors.EVENT_READ)
            if not ready.select(15):raise RuntimeError('Application startup timed out')
        line=process.stdout.readline()
        if not line.startswith('Application at '):raise RuntimeError('Application startup failed: '+process.stderr.read())
        url=line.split(';')[0].removeprefix('Application at ')
        sessions=state/'sessions.json'
        tests=[c['id'] for c in CASES if c['track']==track]
        manifest={'schema_version':1,'owner':'local-pilot-operator','data_class':'synthetic',
                  'target':{'adapter':'application','kind':'authenticated_sqlite_range','url':url,
                            'sessions_file':str(sessions),'sessions_sha256':hashlib.sha256(sessions.read_bytes()).hexdigest()},
                  'tests':tests,'limits':{'requests':100,'seconds':900,'interval_seconds':0,
                                        'timeout_seconds':30,'response_bytes':1048576}}
        if model_url and track=='ai':manifest['target']['model']={'url':model_url,'id':model}
        h.validate(manifest)
        approval={'type':'local operator attestation; not organizational approval','approver':'local-pilot-operator',
                  'purpose':'run','manifest_sha256':h.digest(manifest),'code_sha256':h.code_hash(),
                  'expires_utc':(h.now()+dt.timedelta(minutes=15)).isoformat()}
        started=time.monotonic()
        with contextlib.redirect_stdout(io.StringIO()):code=h.campaign(manifest,approval,directory)
        elapsed=time.monotonic()-started
        campaign=next(directory.glob('campaign-*'));summary=h.read(campaign/'summary.json')
        database=sqlite3.connect(state/'state.sqlite')
        snapshot={'exports':[r[0] for r in database.execute('SELECT actor FROM exports')],
                  'orders':[list(r) for r in database.execute('SELECT id,paid,fulfilled FROM orders ORDER BY id')]}
        database.close()
        audit=[json.loads(l) for l in (state/'audit.jsonl').read_text().splitlines()] if (state/'audit.jsonl').exists() else []
        with contextlib.redirect_stdout(io.StringIO()):h.verify(campaign)
        expected_failure=profile=='vulnerable'
        state_verified=None
        if track=='web':
            orders={row[0]:row[2] for row in snapshot['orders']}
            object_reads=[r for r in audit if r['path']=='/api/records/read' and r['body']['owner']=='bob']
            policy_reads=[r for r in audit if r['path']=='/api/protected/read' and r['body']['dependency']=='offline']
            state_verified=(orders['paid']==1 and orders['unpaid']==int(expected_failure)
                            and snapshot['exports'].count('alice')==(2 if expected_failure else 0)
                            and snapshot['exports'].count('admin')==1
                            and len(object_reads)==2 and all(r['status']==403 for r in object_reads)
                            and len(policy_reads)==2 and all((r['status']==200)==expected_failure for r in policy_reads))
        outcomes_match=(summary['complete'] and len(summary['results'])==len(tests) and
                        all(r['status']==('reproduced_failure' if expected_failure and r['case']!='web-object-access' else 'observed_control_pass')
                            for r in summary['results'])) if track=='web' else None
        report={'outcomes_match_ground_truth':outcomes_match,'track':track,'profile':profile,'complete':summary['complete'],'exit_code':code,
                'elapsed_seconds':elapsed,'requests':summary['requests'],'audit_records':len(audit),
                'independent_state_checks_passed':state_verified,
                'findings':sum(r['status']=='reproduced_failure' for r in summary['results']),
                'inconclusive':sum(r['status']=='inconclusive' for r in summary['results']),
                'known_fixture_misses':sum(r['status']!='reproduced_failure' for r in summary['results'] if r['case']!='web-object-access') if expected_failure and track=='web' else None,
                'false_positives':sum(r['status']=='reproduced_failure' for r in summary['results']) if not expected_failure else None,
                'model_execution':'actual local endpoint' if model_url and track=='ai' else 'none',
                'manual_baseline':'not measured','human_review_effort':'pending human review',
                'provider_cost':'no external provider calls; local compute cost not measured',
                'campaign':str(campaign),'application_state':snapshot}
        h.write(directory/'acceptance.json',report)
        # Separate checkpoint covers both application artifacts and harness evidence.
        hashes={str(p.relative_to(directory)):hashlib.sha256(p.read_bytes()).hexdigest()
                for p in directory.rglob('*') if p.is_file() and p.name!='sessions.json'}
        h.write(directory/'checkpoint.json',hashes)
        return report
    finally:
        process.terminate()
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.kill();process.wait()
        process.stdout.close();process.stderr.close()

def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output-root',type=Path,default=ROOT/'runs');p.add_argument('--model-url');p.add_argument('--model')
    a=p.parse_args()
    if bool(a.model_url)!=bool(a.model):p.error('Provide both --model-url and --model')
    if a.model_url:h.endpoint(a.model_url)
    a.output_root.mkdir(parents=True,exist_ok=True)
    directory=Path(tempfile.mkdtemp(prefix='pilot-',dir=a.output_root)).resolve()
    reports=[run_profile(directory,profile,'web') for profile in ('fixed','vulnerable')]
    if a.model_url:reports += [run_profile(directory,profile,'ai',a.model_url,a.model) for profile in ('fixed','vulnerable')]
    acceptance={'campaigns':reports,'ai_calibration':'executed; inspect outcomes' if a.model_url else 'pending local model endpoint',
                'human_independent_review':'pending','external_targets':'none'}
    h.write(directory/'acceptance.json',acceptance)
    print(json.dumps({'evidence':str(directory),**acceptance},indent=2))
    return 0 if all(r['complete'] and r['independent_state_checks_passed'] and r['outcomes_match_ground_truth']
                    and r['requests']==r['audit_records']==3*sum(1 for x in CASES if x['track']=='web')
                    for r in reports if r['track']=='web') and all(r['complete'] for r in reports) else 2

if __name__=='__main__':raise SystemExit(main())
