#!/usr/bin/env bash
# akamai-waf-check.sh — Akamai WAF detection + baseline + low-signal probe classifier.
#
# Usage:
#   ./akamai-waf-check.sh https://target.example.com [param]
#
#   URL    Target base URL (no query string).
#   param  Optional query parameter name to probe (default: test).
#
# What it does (detection-grade only, no exploitation):
#   1. Fingerprints the edge from response headers/cookies (AkamaiGHost, x-akamai, ak_bmsc/_abck).
#   2. Resolves DNS and shows the CNAME chain (Akamai edge hostnames).
#   3. Takes a benign baseline (status/size/timing).
#   4. Sends one low-signal probe per attack class and classifies each:
#      BLOCKED (403/406 + block markers), REACHED (200 + payload reflected / app error),
#      or PASSED (200, no reflection evidence — may be alert mode or no coverage).
#   5. Checks for Akamai Pragma debug-header leakage.
#
# Run ONLY against systems you own or are authorized to test.
# Note: triggering the WAF can rate-limit your source IP ("penalty box") for minutes.

set -u

URL="${1:-}"
PARAM="${2:-test}"

if [ -z "$URL" ]; then
  echo "Usage: $0 https://target.example.com [param]" >&2
  exit 1
fi

URL="${URL%/}"
HOST="$(printf '%s' "$URL" | sed -E 's#^https?://##; s#/.*$##')"

UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36"

probe() {
  # $1 = label, $2 = encoded payload
  local label="$1" payload="$2"
  local out code time size
  out="$(curl -s -A "$UA" -w '\n__CODE__:%{http_code} __TIME__:%{time_total} __SIZE__:%{size_download}' \
        "${URL}/?${PARAM}=${payload}" 2>/dev/null)"
  code="$(printf '%s' "$out" | sed -n 's/.*__CODE__:\([0-9]*\).*/\1/p')"
  time="$(printf '%s' "$out" | sed -n 's/.*__TIME__:\([0-9.]*\).*/\1/p')"
  size="$(printf '%s' "$out" | sed -n 's/.*__SIZE__:\([0-9]*\).*/\1/p')"
  local body verdict
  body="$(printf '%s' "$out" | sed 's/__CODE__:.*$//')"

  if [ "$code" = "403" ] || [ "$code" = "406" ] \
     || printf '%s' "$body" | grep -qiE 'reference|akamai|access denied|request blocked'; then
    verdict="BLOCKED (edge)"
  elif printf '%s' "$body" | grep -qiE 'sql syntax|you have an error in your sql|alert\(1\)|\bpasswd:'; then
    verdict="REACHED APP (payload evidence in response)"
  elif [ "$code" = "200" ]; then
    verdict="PASSED (200; check alert mode / no coverage)"
  else
    verdict="HTTP $code (review manually)"
  fi

  printf '%-16s code=%s time=%ss size=%s -> %s\n' "$label" "${code:-?}" "${time:-?}" "${size:-?}" "$verdict"
}

echo "== Target: $URL (param: $PARAM) =="
echo

echo "-- DNS --"
if command -v dig >/dev/null 2>&1; then
  dig +short "$HOST"
else
  getent hosts "$HOST" || true
fi
echo

echo "-- Headers (fingerprint) --"
curl -sI -A "$UA" "$URL" | egrep -i '^(HTTP/|server:|x-akamai|set-cookie:|x-cache)' || true
echo "(Bot Manager cookies to look for: ak_bmsc, _abck)"
echo

echo "-- Baseline --"
curl -s -A "$UA" -o /dev/null -w 'benign: code=%{http_code} time=%{time_total}s size=%{size_download}\n' \
  "${URL}/?${PARAM}=hello"
echo

echo "-- Low-signal probes --"
probe "SQLi"  "'%20OR%201=1--"
probe "XSS"   "%3Cscript%3Ealert(1)%3C/script%3E"
probe "Traversal" "..%2f..%2fetc%2fpasswd"
probe "CmdInject" "%7C%20cat%20/etc/passwd"
probe "SSTI"  "%24%7B%7B7*7%7D%7D"
echo

echo "-- Pragma debug-header check --"
LEAK="$(curl -s -A "$UA" -H 'Pragma: akamai-x-get-true-cache-key, akamai-x-check-cacheable' -D - -o /dev/null "$URL" \
        | egrep -i '^x-akamai' || true)"
if [ -n "$LEAK" ]; then
  echo "LEAK: Akamai debug headers answered:"
  printf '%s\n' "$LEAK"
else
  echo "No x-akamai debug headers returned (good)."
fi
echo

echo "Done. Classify per the playbook: blocked-at-edge vs reached-app vs passed(200)."
echo "Next manual steps: origin discovery (DNS history, crt.sh), staging-vs-prod policy, JSON-depth and encoding-differential tests."
