#!/usr/bin/env python3
"""Collect WAF observations without inferring application exploitation."""
import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time
from urllib.parse import urlencode, urlsplit
from evidence import response_details, save_analysis
from scope import Campaign, ScopeError, validate as validate_scope

PROBES = [
    ("control", "hello"),
    ("sqli", "' OR 1=1--"),
    ("xss", "<script>alert(1)</script>"),
    ("traversal", "../../etc/passwd"),
    ("command", "| cat /etc/passwd"),
    ("ssti", "{{7*7}}"),
]


def classify(exit_code, status, body):
    if exit_code or status == 0:
        return "request_failed"
    if status == 429:
        return "rate_limited"
    if status in (403, 406) or re.search(
        r"\b(?:access denied|request blocked)\b", body, re.I
    ):
        return "suspected_block"
    return "inconclusive"


def resolve_public_endpoint(url):
    """Resolve the target and refuse loopback/private/link-local/metadata addresses.

    Returns (ip, host, port). curl is pinned to this ip so DNS rebinding cannot
    swing the request onto an internal address after the check.
    """
    parsed = urlsplit(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    addresses = {info[4][0] for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
    if not addresses:
        raise ScopeError(f"Target {host} does not resolve")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        # Unwrap IPv4-mapped IPv6 (::ffff:a.b.c.d) so a mapped internal address
        # cannot read as global on interpreters predating the is_global fix.
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if not ip.is_global or ip.is_multicast:
            raise ScopeError(f"Target {host} resolves to non-global address {address}")
    return sorted(addresses)[0], host, port


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="Approved HTTP(S) endpoint; no query or fragment")
    parser.add_argument("param", nargs="?", default="test")
    parser.add_argument("--output", type=Path, help="New evidence directory")
    parser.add_argument("--scope", type=Path, help="Explicit approved WAF campaign scope")
    parser.add_argument("--connect-timeout", type=float, default=5)
    parser.add_argument("--max-time", type=float, default=15)
    parser.add_argument("--interval", type=float, default=1,
                        help="Seconds between requests (minimum 1)")
    args = parser.parse_args(argv)
    try:
        parsed = urlsplit(args.url)
        valid = (parsed.scheme in ("http", "https") and parsed.hostname
                 and not parsed.username and not parsed.password
                 and not parsed.query and not parsed.fragment
                 and "?" not in args.url and "#" not in args.url
                 and not re.search(r"[\s\x00-\x1f\x7f]", args.url))
        parsed.port  # Validate malformed port numbers too.
    except ValueError:
        valid = False
    if not valid:
        parser.error("URL must be HTTP(S), without credentials, whitespace, query or fragment")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", args.param):
        parser.error("Parameter must be a simple name, up to 64 characters")
    if not (0 < args.connect_timeout <= args.max_time <= 120):
        parser.error("Timeouts must satisfy 0 < connect-timeout <= max-time <= 120")
    if not (1 <= args.interval <= 60):
        parser.error("interval must be between 1 and 60 seconds")
    return args


def main(argv=None):
    # Also protect files when called programmatically, not just through the CLI.
    os.umask(0o077)
    args = parse_args(argv)
    try:
        approved = validate_scope(args.scope,args.url,args.param,args.interval)
    except (ValueError,KeyError,TypeError,OSError) as exc:
        print('Collection denied: '+str(exc),file=sys.stderr)
        return 2
    campaign=Campaign(approved)
    selected=[next(p for p in PROBES if p[0]==identifier) for identifier in approved['probes']]
    try:
        pinned_ip, pin_host, pin_port = resolve_public_endpoint(args.url)
    except (ScopeError, OSError, ValueError) as exc:
        print('Collection denied: '+str(exc), file=sys.stderr)
        return 2
    curl = shutil.which("curl")
    if not curl:
        print("curl is required", file=sys.stderr)
        return 2
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    root = args.output or Path("results") / stamp
    try:
        root.mkdir(parents=True, exist_ok=False, mode=0o700)
    except OSError as exc:
        print(f"Cannot create new evidence directory: {exc}", file=sys.stderr)
        return 2
    (root / 'scope.json').write_text(json.dumps(approved,indent=2)+'\n')
    records = []
    stopped = None
    def checkpoint(complete=False, reason='Collection in progress'):
        report = {"schema_version": 2, "target": args.url,
                  "complete": complete, "stop_reason": reason, "observations": records,
                  "planned_probes": approved["probes"],
                  "untested_probes": [label for label, _ in PROBES
                                     if label not in {r['label'] for r in records}],
                  "note": "No verdict confirms edge enforcement, app reachability or exploitation. Correlate logs manually."}
        (root / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        save_analysis(root, report)
    checkpoint()
    for index, (label, payload) in enumerate(selected):
        try:
            campaign.remaining()
            if index:
                time.sleep(min(args.interval,campaign.remaining()))
            remaining=campaign.reserve()
        except ScopeError as exc:
            stopped=str(exc)
            break
        folder = root / f"{index:02d}-{label}"
        folder.mkdir(mode=0o700)
        url = args.url + "?" + urlencode({args.param: payload})
        # -q disables user curl configuration; no redirects, cookies, callbacks,
        # extra protocols, retries, or disabled TLS verification are enabled.
        command = [curl, "-q", "--silent", "--show-error", "--globoff",
                   "--path-as-is", "--proto", "=http,https", "--noproxy", "*",
                   "--resolve", f"{pin_host}:{pin_port}:{pinned_ip}",
                   "--connect-timeout", str(min(args.connect_timeout,remaining)),
                   "--max-time", str(min(args.max_time,remaining)), "--max-filesize", "1048576",
                   "--dump-header", str(folder / "response-headers.txt"),
                   "--output", str(folder / "response-body.bin"),
                   "--trace-ascii", str(folder / "curl-trace.txt"), "--trace-time",
                   "--write-out", "%{http_code}\n%{time_total}\n%{size_download}\n%{json}",
                   "--url", url]
        timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
        request = {"method": "GET", "url": url, "label": label,
                   "parameter": args.param, "payload": payload,
                   "timestamp": timestamp, "curl_argv": command}
        (folder / "request.json").write_text(json.dumps(request, indent=2) + "\n")
        try:
            result = subprocess.run(command, capture_output=True, text=True,
                                    timeout=min(args.max_time,remaining) + 1)
            exit_code = result.returncode
            stdout, stderr = result.stdout, result.stderr
        except (subprocess.TimeoutExpired, OSError) as exc:
            exit_code, stdout, stderr = 124, "", str(exc)
        (folder / "curl-stdout.txt").write_text(stdout)
        (folder / "curl-stderr.txt").write_text(stderr)
        metrics = stdout.splitlines()
        try:
            status = int(metrics[0])
            duration = float(metrics[1])
            size = int(metrics[2])
        except (ValueError, IndexError):
            status, duration, size = 0, None, None
            exit_code = exit_code or 1
        body_path = folder / "response-body.bin"
        body = body_path.read_bytes().decode("utf-8", "replace") if body_path.exists() else ""
        verdict = classify(exit_code, status, body)
        try:
            detail_metrics = json.loads("\n".join(metrics[3:]))
        except ValueError:
            detail_metrics = {"http_code": status, "time_total": duration,
                              "size_download": size,
                              "detail_note": "Extended curl JSON metrics unavailable"}
        response_details(folder, detail_metrics, exit_code)
        record = {"label": label, "timestamp": timestamp, "status": status,
                  "curl_exit_code": exit_code, "duration_seconds": duration,
                  "size_bytes": size, "verdict": verdict,
                  "evidence_directory": folder.name}
        records.append(record)
        checkpoint()
        print(f"{label:12} HTTP {status:03} {verdict}")
        try:campaign.remaining()
        except ScopeError as exc:
            stopped=str(exc)
            break
        if (verdict == "request_failed" or status == 429 or status >= 500
                or (label == "control" and (verdict == "suspected_block" or not 200 <= status < 300))):
            stopped = f"Stopped after {label}: request failure, unsafe baseline, rate limit or server error"
            break
    complete = len(records) == len(selected) and stopped is None
    checkpoint(complete, stopped)
    print(f"Evidence: {root.resolve()}")
    print(f"Detailed analysis: {(root / 'analysis.json').resolve()}")
    return 0 if complete else 1


if __name__ == "__main__":
    # Evidence may contain sensitive responses; restrict newly created files.
    os.umask(0o077)
    sys.exit(main())
