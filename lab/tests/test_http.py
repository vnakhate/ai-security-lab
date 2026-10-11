import contextlib
import datetime as dt
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import harness as h
from catalog import CASES
from fixture_server import server

class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.d=Path(self.tmp.name)
        self.services=[]
        self.m={"schema_version":1,"owner":"test","data_class":"synthetic",
                "target":{"adapter":"fixture","profile":"fixed"},"tests":[c["id"] for c in CASES],
                "limits":{"requests":100,"seconds":15,"interval_seconds":0,"timeout_seconds":1,"response_bytes":4096}}

    def serve(self,s):
        self.services.append(s)
        thread=threading.Thread(target=s.serve_forever,daemon=True);thread.start()
        return f"http://127.0.0.1:{s.server_port}"

    def tearDown(self):
        for s in self.services:s.shutdown();s.server_close()
        self.tmp.cleanup()

    def attest(self,purpose):
        a={"manifest_sha256":h.digest(self.m),"code_sha256":h.code_hash(),"purpose":purpose,"approver":"test",
           "expires_utc":(h.now()+dt.timedelta(minutes=5)).isoformat()}
        return a

    def test_http_fixture_campaign(self):
        self.m["target"]={"adapter":"http","url":self.serve(server(0,"fixed"))}
        h.validate(self.m)
        with contextlib.redirect_stdout(io.StringIO()):code=h.campaign(self.m,self.attest("run"),self.d)
        self.assertEqual(code,0)
        summary=h.read(next(self.d.glob("campaign-*"))/"summary.json")
        self.assertFalse(summary["fixture_calibration"])
        self.assertEqual(summary["requests"],3*len(CASES))

    def test_redirect_is_saved_and_never_followed(self):
        class Redirect(BaseHTTPRequestHandler):
            calls=0
            def do_POST(self):
                type(self).calls+=1
                self.send_response(302);self.send_header("Location","http://example.com/")
                self.send_header("Content-Length","0");self.end_headers()
            def log_message(self,*a):pass
        self.m["target"]={"adapter":"http","url":self.serve(HTTPServer(("127.0.0.1",0),Redirect))}
        e=h.Evidence(self.d)
        try:
            b=h.Broker(self.m,e,self.attest("run"))
            with self.assertRaisesRegex(h.Denied,"Redirect"):b.send(CASES[0]["control"])
            self.assertEqual(Redirect.calls,1)
        finally:e.close()
        rows=[json.loads(x) for x in (self.d/"events.jsonl").read_text().splitlines()]
        self.assertEqual(rows[-1]["data"]["status"],302)

    def test_local_model_assistance_cannot_expand_scope(self):
        class Planner(BaseHTTPRequestHandler):
            selected=["web-object-access"]
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                body={"choices":[{"message":{"content":json.dumps({"test_ids":self.selected,"rationale":"Test authorization"})}}]}
                raw=json.dumps(body).encode();self.send_response(200)
                self.send_header("Content-Length",str(len(raw)));self.end_headers();self.wfile.write(raw)
            def log_message(self,*a):pass
        self.m["planner"]={"url":self.serve(HTTPServer(("127.0.0.1",0),Planner))+"/v1/chat/completions","model":"mock"}
        manifest=self.d/"scope.json";ap=self.d/"approval.json"
        h.write(manifest,self.m);h.write(ap,self.attest("assist"))
        args=["assist","--manifest",str(manifest),"--approval",str(ap),"--output-root",str(self.d/"runs")]
        with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(h.main(args),0)
        Planner.selected=["arbitrary-shell"]
        with contextlib.redirect_stderr(io.StringIO()): self.assertEqual(h.main(args),2)
        self.assertEqual(len(list((self.d/"runs").glob("planning-*/suggestion.json"))),1)

    def test_pyrit_export_preserves_json_input_and_categories(self):
        manifest=self.d/"scope.json";out=self.d/"seeds.json";h.write(manifest,self.m)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(h.main(["export-pyrit","--manifest",str(manifest),"--output",str(out)]),0)
        seeds=h.read(out)["seeds"]
        self.assertEqual(len(seeds),8)
        self.assertEqual(json.loads(seeds[0]["value"])["tenant"],"alice")
        self.assertIn("LLM01:2026",seeds[0]["metadata"]["owasp"])

    def test_slow_response_cannot_extend_absolute_deadline(self):
        class Slow(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(200);self.send_header("Content-Length","2000");self.end_headers()
                try:
                    for _ in range(100):
                        self.wfile.write(b"x");self.wfile.flush();time.sleep(0.02)
                except (BrokenPipeError,ConnectionResetError):pass
            def log_message(self,*a):pass
        self.m["target"]={"adapter":"http","url":self.serve(HTTPServer(("127.0.0.1",0),Slow))}
        self.m["limits"]["timeout_seconds"]=0.1
        e=h.Evidence(self.d);started=time.monotonic()
        try:
            with self.assertRaises((h.Denied,OSError)):
                h.Broker(self.m,e,self.attest("run")).send(CASES[0]["control"])
            self.assertLess(time.monotonic()-started,1)
        finally:e.close()

    def test_oversized_response_is_saved_bounded_and_not_scored(self):
        class Large(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                raw=b"x"*5000;self.send_response(200)
                self.send_header("Content-Length",str(len(raw)));self.end_headers();self.wfile.write(raw)
            def log_message(self,*a):pass
        self.m["target"]={"adapter":"http","url":self.serve(HTTPServer(("127.0.0.1",0),Large))}
        e=h.Evidence(self.d)
        try:
            with self.assertRaisesRegex(h.Denied,"evidence limit"):
                h.Broker(self.m,e,self.attest("run")).send(CASES[0]["control"])
        finally:e.close()
        data=json.loads((self.d/"events.jsonl").read_text().splitlines()[-1])["data"]
        self.assertTrue(data["truncated"]);self.assertIsNone(data["body"])
        self.assertEqual(len(data["raw_body_utf8"]),4096)

if __name__=="__main__":unittest.main()
