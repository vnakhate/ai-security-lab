#!/usr/bin/env python3
"""Optional loopback fixture server. No model, scanner, Docker or shell execution."""
import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from fixtures import Fixture

def server(port, profile):
    fixture = Fixture(profile)
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 65536: raise ValueError("Invalid request length")
                body = json.loads(self.rfile.read(length))
                result = fixture.send({"method":"POST", "path":self.path, "body":body})
            except (ValueError, KeyError, TypeError):
                result = {"status":400, "body":{"error":"Invalid fixture request"}}
            raw = json.dumps(result["body"]).encode()
            self.send_response(result["status"])
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        def log_message(self, *args): pass
    return HTTPServer(("127.0.0.1", port), Handler)

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--profile", choices=["fixed","vulnerable"], default="fixed")
    a = p.parse_args()
    s = server(a.port, a.profile)
    print(f"Synthetic {a.profile} fixtures at http://127.0.0.1:{a.port}/", flush=True)
    try: s.serve_forever()
    except KeyboardInterrupt: pass
    finally: s.server_close()
