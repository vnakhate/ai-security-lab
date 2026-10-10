import contextlib
import datetime as dt
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import harness as h
from catalog import CASES, BY_ID
from fixtures import Fixture

class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.m = {"schema_version":1,"owner":"test","data_class":"synthetic",
                  "target":{"adapter":"fixture","profile":"fixed"},
                  "tests":[c["id"] for c in CASES],
                  "limits":{"requests":100,"seconds":15,"interval_seconds":0,"timeout_seconds":1,"response_bytes":4096}}
        self.a = {"manifest_sha256":h.digest(self.m),"code_sha256":h.code_hash(),"purpose":"run","approver":"test",
                  "expires_utc":(h.now()+dt.timedelta(minutes=5)).isoformat()}

    def tearDown(self): self.tmp.cleanup()

    def run_campaign(self, profile):
        self.m["target"]["profile"] = profile
        self.a["manifest_sha256"] = h.digest(self.m)
        with contextlib.redirect_stdout(io.StringIO()): code = h.campaign(self.m,self.a,self.d)
        run = next(self.d.glob("campaign-*"))
        return code,run,h.read(run/"summary.json")

    def test_fixed_and_vulnerable_ground_truth(self):
        for c in CASES:
            for profile,expected in (("fixed",False),("vulnerable",True)):
                f=Fixture(profile)
                self.assertTrue(h.control_valid(c,f.send(c["control"])),c["id"])
                self.assertIs(h.score(c,f.send(c["attack"])),expected,c["id"])

    def test_fixed_suite_evidence_and_uncovered_categories(self):
        code,run,summary=self.run_campaign("fixed")
        self.assertEqual(code,0); self.assertTrue(summary["complete"])
        self.assertEqual(summary["requests"],3*len(CASES))
        self.assertEqual(len(summary["results"]),len(CASES))
        self.assertEqual(h.read(run/"coverage.json")["LLM05:2026"]["scope"],"Not tested")
        with contextlib.redirect_stdout(io.StringIO()): h.verify(run)
        first=json.loads((run/"events.jsonl").read_text().splitlines()[1])
        self.assertEqual(first["kind"],"request")

    def test_vulnerable_suite_reports_reproduced_failures(self):
        code,run,summary=self.run_campaign("vulnerable")
        self.assertEqual(code,1);self.assertTrue(summary["complete"])
        self.assertTrue(all(r["status"]=="reproduced_failure" for r in summary["results"]))

    def test_evidence_tampering_detected(self):
        _,run,_=self.run_campaign("fixed")
        (run/"REPORT.md").write_text("changed")
        with self.assertRaises(h.Denied): h.verify(run)

    def test_scope_rejects_external_hosts_and_malformed_endpoints(self):
        for url in ("http://example.com:80/","http://169.254.169.254:80/","http://192.168.1.1:80/",
                    "http://localhost:80/","http://127.0.0.1/","http://user:pass@127.0.0.1:80/",
                    "http://127.0.0.1:80/?x=1","https://127.0.0.1:80/"):
            with self.assertRaises(h.Denied,msg=url):h.endpoint(url)
        h.endpoint("http://127.0.0.1:8765/");h.endpoint("http://[::1]:8765/")

    def test_manifest_rejects_bad_limits_and_unapproved_tests(self):
        for v in (-1,101,float("nan"),True):
            self.m["limits"]["requests"]=v
            with self.assertRaises(h.Denied):h.validate(self.m)
        self.m["limits"]["requests"]=100;self.m["tests"]=["arbitrary-shell"]
        with self.assertRaises(h.Denied):h.validate(self.m)

    def test_expired_changed_scope_and_changed_code_approvals_denied(self):
        ap=self.d/"approval.json";h.write(ap,self.a)
        h.approval(self.m,ap,"run")
        for change in ({"expires_utc":(h.now()-dt.timedelta(seconds=1)).isoformat()},
                       {"code_sha256":"wrong"},{"purpose":"assist"}):
            h.write(ap,{**self.a,**change})
            with self.assertRaises(h.Denied):h.approval(self.m,ap,"run")
        h.write(ap,self.a);self.m["tests"]=self.m["tests"][:1]
        with self.assertRaises(h.Denied):h.approval(self.m,ap,"run")

    def test_stop_budget_path_and_time_enforced(self):
        e=h.Evidence(self.d);b=h.Broker(self.m,e,self.a)
        try:
            (self.d/"STOP").touch()
            with self.assertRaises(h.Denied):b.send(CASES[0]["control"])
            (self.d/"STOP").unlink()
            with self.assertRaises(h.Denied):b.send({"method":"POST","path":"/other","body":{}})
            b.count=100
            with self.assertRaises(h.Denied):b.send(CASES[0]["control"])
            b.count=0;b.started-=20
            with self.assertRaises(h.Denied):b.send(CASES[0]["control"])
        finally:e.close()

    def test_missing_ai_instrumentation_is_inconclusive(self):
        self.assertIsNone(h.score(BY_ID["ai-injection"],{"status":200,"body":{"text":"Denied"}}))
        self.assertIsNone(h.score(BY_ID["ai-output"],{"status":200,"body":{"trace":{"sink_executed":"false"}}}))
        self.assertFalse(h.control_valid(CASES[0],{"status":200,"body":{}}))

    def test_response_types_and_campaign_owned_expectations(self):
        for value in ("true", 1, None, [], {}):
            response={"status":200,"body":{"export_completed":value}}
            self.assertIsNone(h.score(BY_ID["web-role-access"],response))
        self.assertTrue(h.score(BY_ID["web-object-access"],
                               {"status":200,"body":{"record_owner":"charlie"}}))
        self.assertTrue(h.score(BY_ID["ai-retrieval"],
                               {"status":200,"body":{"trace":{"retrieved_tenants":["charlie"]}}}))
        self.assertIsNone(h.score(BY_ID["ai-retrieval"],
                                 {"status":200,"body":{"trace":{"retrieved_tenants":[3]}}}))
        self.assertTrue(h.score(BY_ID["ai-consumption"],
                               {"status":200,"body":{"trace":{"tool_calls":4,"tool_limit":100}}}))
        self.assertTrue(h.score(BY_ID["ai-tool-approval"],
                               {"status":200,"body":{"trace":{"tool_calls":1,"tool_attempted":True,
                                "tool_executed":True,"tool_authorized":True}}}))

    def test_refusing_all_legitimate_ai_tasks_invalidates_baseline(self):
        for c in CASES:
            if c["track"] == "ai":
                self.assertFalse(h.control_valid(c,{"status":200,"body":{"text":"Denied"}}),c["id"])
        response=Fixture("fixed").send(BY_ID["ai-tool-approval"]["control"])
        response["body"]["trace"]["tool_executed"]=False
        self.assertFalse(h.control_valid(BY_ID["ai-tool-approval"],response))
        response=Fixture("fixed").send(BY_ID["ai-consumption"]["control"])
        response["body"]["trace"]["tool_calls"]=True
        self.assertFalse(h.control_valid(BY_ID["ai-consumption"],response))

    def test_budget_preflight_sends_nothing(self):
        self.m["limits"]["requests"]=1
        with patch.object(h.Broker,"send") as send:
            with self.assertRaises(h.Denied):h.campaign(self.m,self.a,self.d)
            send.assert_not_called()

    def test_transport_failure_preserves_incomplete_evidence(self):
        with patch.object(h.Broker,"send",side_effect=TimeoutError("timeout")):
            code,run,summary=self.run_campaign("fixed")
        self.assertEqual(code,2);self.assertFalse(summary["complete"])
        self.assertIn("timeout",summary["error"])
        self.assertTrue((run/"sha256.json").exists())

if __name__=="__main__":unittest.main()
