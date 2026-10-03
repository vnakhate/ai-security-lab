import datetime as dt
import json
from pathlib import Path
import scope

def make_scope(path,url='https://example.invalid/api/search',parameter='test',interval=1,**changes):
    record={'schema_version':1,'purpose':'waf-collection','owner':'test','approver':'test',
            'target_url':url,'parameter':parameter,'method':'GET','probes':list(scope.PROBE_IDS),
            'expires_utc':(scope.now()+dt.timedelta(minutes=5)).isoformat(),'code_sha256':scope.code_hash(),
            'limits':{'requests':6,'seconds':180,'interval_seconds':interval},**changes}
    Path(path).write_text(json.dumps(record))
    return record
