#!/usr/bin/env python3
"""Loopback out-of-band callback sink.

Proves exfiltration and SSRF independently of what a model or target reports: a
case plants a payload that makes the target call http://127.0.0.1:<port>/<token>,
then asserts the token arrived here. Loopback-only. Callbacks are kept in memory
and, when an evidence path is given, appended to a symlink-refusing JSONL file.
"""
import json
import os
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs


def _token(path):
    parts = urlsplit(path)
    segments = [s for s in parts.path.split('/') if s]
    if segments:
        return segments[0]
    return (parse_qs(parts.query).get('t') or [''])[0]


class Sink:
    """A loopback HTTP collector. Use as a context manager."""

    def __init__(self, evidence_path=None):
        self.hits = []
        self.evidence_path = evidence_path
        self._lock = threading.Lock()
        self._server = HTTPServer(('127.0.0.1', 0), self._handler())
        self.port = self._server.server_port
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def _handler(self):
        sink = self
        class Handler(BaseHTTPRequestHandler):
            def _record(self):
                length = int(self.headers.get('Content-Length') or 0)
                body = self.rfile.read(min(length, 65536)).decode('utf-8', 'replace') if length else ''
                sink._append({'timestamp': datetime.now(timezone.utc).isoformat(),
                              'method': self.command, 'path': self.path,
                              'token': _token(self.path), 'body': body,
                              'user_agent': self.headers.get('User-Agent', '')})
                self.send_response(204)
                self.end_headers()
            do_GET = _record
            do_POST = _record

            def log_message(self, format, *args):
                pass
        return Handler

    def _append(self, record):
        with self._lock:
            self.hits.append(record)
            if not self.evidence_path:
                return
            # Best-effort evidence, refusing a pre-planted symlink (O_NOFOLLOW).
            try:
                fd = os.open(self.evidence_path,
                             os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
                try:
                    os.write(fd, (json.dumps(record) + '\n').encode())
                    os.fsync(fd)
                finally:
                    os.close(fd)
            except OSError:
                pass

    def url(self, token):
        return f'http://127.0.0.1:{self.port}/{token}'

    def received(self, token):
        with self._lock:
            return [hit for hit in self.hits if hit['token'] == token]

    def start(self):
        self._thread.start()
        return self

    def close(self):
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.close()
