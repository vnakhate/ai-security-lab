"""Build local analysis artifacts from captured requests and raw responses."""
import hashlib
import html
import json
from pathlib import Path
import re


def response_details(folder, metrics, exit_code):
    headers_path = folder / 'response-headers.txt'
    raw_headers = headers_path.read_text(errors='replace') if headers_path.exists() else ''
    headers = []
    for line in raw_headers.splitlines():
        if ':' in line and not line.startswith('HTTP/'):
            name, value = line.split(':', 1)
            headers.append({'name': name.strip(), 'value': value.strip()})
    body_path = folder / 'response-body.bin'
    raw = body_path.read_bytes() if body_path.exists() else b''
    content_type = next((h['value'] for h in reversed(headers)
                         if h['name'].lower() == 'content-type'), '')
    charset = re.search(r'charset\s*=\s*["\']?([\w.-]+)', content_type, re.I)
    encoding = charset.group(1) if charset else 'utf-8'
    try:
        decoded = raw.decode(encoding, errors='replace')
    except LookupError:
        encoding = 'utf-8'
        decoded = raw.decode(encoding, errors='replace')
    (folder / 'response-text.txt').write_text(decoded, encoding='utf-8')
    references = re.findall(r'Reference\s*#?\s*([\w.-]+)', html.unescape(decoded), re.I)
    details = {'curl_metrics': metrics, 'curl_exit_code': exit_code,
               'headers': headers, 'content_type': content_type,
               'body_present': body_path.exists(), 'captured_body_bytes': len(raw),
               'body_sha256': hashlib.sha256(raw).hexdigest() if body_path.exists() else None,
               'text_decode_encoding': encoding, 'reference_numbers': references,
               'transfer_completed': exit_code == 0, 'body_text': decoded,
               'note': 'Raw body is authoritative; decoded text may replace invalid bytes. Failed transfers may be partial.'}
    (folder / 'response.json').write_text(json.dumps(details, indent=2) + '\n')
    return details


def save_analysis(root, report):
    details = dict(report)
    details['observations'] = []
    for record in report['observations']:
        item = dict(record)
        folder = root / record['evidence_directory']
        item['request'] = json.loads((folder / 'request.json').read_text())
        item['response'] = json.loads((folder / 'response.json').read_text())
        item['curl_error'] = (folder / 'curl-stderr.txt').read_text()
        details['observations'].append(item)
    (root / 'analysis.json').write_text(json.dumps(details, indent=2) + '\n')
    lines = ['# WAF observation report', '', f"Target: {report['target']}",
             f"Collection complete: {report['complete']}",
             f"Stop/progress reason: {report['stop_reason'] or 'none'}",
             f"Untested: {', '.join(report['untested_probes']) or 'none'}", '',
             '| Probe | HTTP | Verdict | Seconds | Bytes | Evidence |',
             '|---|---|---|---|---|---|']
    for row in report['observations']:
        lines.append(f"| {row['label']} | {row['status']} | {row['verdict']} | {row['duration_seconds']} | {row['size_bytes']} | {row['evidence_directory']}/ |")
    lines += ['', 'Full request/response details: analysis.json. Raw bodies, headers and curl traces are in each request folder.',
              '', 'Verdicts are observations only. Transfer errors override HTTP status; incomplete coverage is not a pass.']
    (root / 'analysis-report.md').write_text('\n'.join(lines) + '\n')
    manifest = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(root.rglob('*')) if p.is_file() and p.name != 'sha256-manifest.json'}
    (root / 'sha256-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
