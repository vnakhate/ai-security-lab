#!/usr/bin/env python3
"""Explicit local operator scope for WAF collection; no authenticated approval service."""
import argparse
import datetime as dt
import hashlib
import json
import math
from pathlib import Path
import time

ROOT=Path(__file__).resolve().parent
PROBE_IDS=('control','sqli','xss','traversal','command','ssti')

class ScopeError(ValueError):pass

def now():return dt.datetime.now(dt.timezone.utc)

def code_hash():
    names=('scope.py','waf_check.py','evidence.py','run_assessment.py','akamai-waf-check.sh','run-waf-assessment.sh')
    return hashlib.sha256(json.dumps({n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in names},sort_keys=True).encode()).hexdigest()

def validate(path,url,param,interval):
    if not path:raise ScopeError('Explicit --scope is required before WAF collection')
    scope=json.loads(Path(path).read_text())
    if not isinstance(scope,dict) or scope.get('schema_version')!=1 or scope.get('purpose')!='waf-collection':
        raise ScopeError('WAF collection scope schema 1 required')
    for key in ('owner','approver'):
        if not isinstance(scope.get(key),str) or not scope[key].strip():raise ScopeError('Named owner and approver required')
    if scope.get('target_url')!=url or scope.get('parameter')!=param or scope.get('method')!='GET':
        raise ScopeError('Target, parameter or method differs from approved scope')
    if scope.get('code_sha256')!=code_hash():raise ScopeError('Collector code changed; review and renew scope')
    try:expiry=dt.datetime.fromisoformat(scope['expires_utc'])
    except (KeyError,TypeError,ValueError):raise ScopeError('Scope expiry is invalid')
    if expiry.tzinfo is None or expiry<=now():raise ScopeError('Scope is expired or has no timezone')
    probes=scope.get('probes')
    if (not isinstance(probes,list) or not probes or probes[0]!='control'
        or not all(isinstance(x,str) and x in PROBE_IDS for x in probes) or len(probes)!=len(set(probes))):
        raise ScopeError('Distinct permitted probes with a benign control first are required')
    limits=scope.get('limits',{})
    if not isinstance(limits,dict):raise ScopeError('Scope limits must be an object')
    for key,low,high in (('requests',len(probes),6),('seconds',1,900),('interval_seconds',1,60)):
        value=limits.get(key)
        if type(value) not in (int,float) or not math.isfinite(value) or not low<=value<=high:raise ScopeError('Invalid scope limit: '+key)
    if type(limits['requests']) is not int or limits['interval_seconds']!=interval:
        raise ScopeError('Request count must be an integer and interval must match scope')
    return scope

class Campaign:
    def __init__(self,scope):self.scope=scope;self.started=time.monotonic();self.requests=0
    def remaining(self):
        seconds=min(self.scope['limits']['seconds']-(time.monotonic()-self.started),
                    (dt.datetime.fromisoformat(self.scope['expires_utc'])-now()).total_seconds())
        if seconds<=0:raise ScopeError('Scope expired or campaign time budget exhausted')
        return seconds
    def reserve(self):
        remaining=self.remaining()
        if self.requests>=self.scope['limits']['requests']:raise ScopeError('Scope request budget exhausted')
        self.requests+=1
        return remaining

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target',required=True);p.add_argument('--parameter',default='test')
    p.add_argument('--owner',required=True);p.add_argument('--approver',required=True)
    p.add_argument('--minutes',type=int,default=60);p.add_argument('--interval',type=float,default=10)
    p.add_argument('--seconds',type=float,default=180);p.add_argument('--probes',nargs='+',choices=PROBE_IDS,default=list(PROBE_IDS))
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if not 1<=a.minutes<=120:p.error('Expiry must be 1–120 minutes')
    from waf_check import parse_args
    parse_args([a.target,a.parameter,'--interval',str(a.interval)])
    record={'schema_version':1,'purpose':'waf-collection','owner':a.owner,'approver':a.approver,
            'approval_type':'local operator attestation; obtain actual asset authorization separately',
            'target_url':a.target,'parameter':a.parameter,'method':'GET','probes':a.probes,
            'expires_utc':(now()+dt.timedelta(minutes=a.minutes)).isoformat(),'code_sha256':code_hash(),
            'limits':{'requests':len(a.probes),'seconds':a.seconds,'interval_seconds':a.interval}}
    if a.output.exists() or a.output.is_symlink():p.error('Refusing to overwrite scope')
    a.output.parent.mkdir(parents=True,exist_ok=True)
    # Validate without creating a reusable malformed attestation.
    import tempfile,os
    fd,tmp=tempfile.mkstemp(dir=a.output.parent)
    try:
        with os.fdopen(fd,'w') as f:f.write(json.dumps(record,indent=2)+'\n')
        validate(tmp,a.target,a.parameter,a.interval)
        os.link(tmp,a.output)
    finally:Path(tmp).unlink()
    print(str(a.output))

if __name__=='__main__':main()
