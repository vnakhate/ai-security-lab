# WAF assessment package — revised 2026-10-02

This package replaces the execution guidance in the original archive. The archive directory was moved outside this project; its new location is not recorded here. It is not required to run the lab. Its duplicate `zip-review/` extraction was removed after archive verification. `akamai-waf-check.original.sh` is retained for review only; do not use its verdicts for acceptance decisions.

## Contents

- `waf-pentest-thorough-plan-20261002.md`: authoritative engagement plan and acceptance gates.
- `akamai-waf-pentest-playbook.md`: bounded execution and evidence procedures.
- `waf-pentest-plan-template-20261002.md`: engagement-specific scope and test matrix.
- `akamai-waf-check.sh` and `waf_check.py`: GET-query observation collector.
- `tests/test_waf_check.py`: offline regression tests; no live target connections.

## Local validation

From the project root, run:

```bash
cd /Users/venky/work/preprod/lab
./lab/run-lab.sh waf --check-only
```

This runs offline checks only. It sends no target requests. The lab launcher requires the `waf` command and its options; do not run it without a command.

For direct checks, first change into this module:

```bash
cd /Users/venky/work/preprod/lab/lab/waf-assessment
bash -n akamai-waf-check.sh
python3 -m unittest discover -s tests -v
```

## One-command launcher

For offline validation from any directory:

```bash
/Users/venky/work/preprod/lab/lab/waf-assessment/run-waf-assessment.sh --check-only
```

The launcher has no default external destination. Active collection requires an explicit URL and `--scope`. It validates shell syntax and runs offline tests before collection. Each invocation uses a unique `runs/` folder. Blocked controls, redirects, rate limits and server errors stop collection.

Create a reviewed scope with `scope.py` as shown in the project root README. Then run:

```bash
./run-waf-assessment.sh --check-only
./run-waf-assessment.sh https://approved.example/api/search --param q --interval 10 --scope ../campaigns/waf-scope.json
```

The scope binds owner, local approver attestation, exact URL, parameter, GET method, selected probes, collector source hash, expiry, pacing, request cap and elapsed-time cap. It is checked before any collection and before each request. It does not authenticate organizational approval identities or constrain DNS resolution through independent network enforcement.

Use alternate hosts only with authorization. A local validation/setup failure returns 2 without target requests. Ctrl+C returns 130 and retains any partial evidence. This launcher requires the accompanying Python collector and tests; distribute the package together.

## Approved assessment run

After completing the scope template, run from this directory:

```bash
./akamai-waf-check.sh https://approved.example/api/search q --interval 10 --scope ../campaigns/waf-scope.json --output results/run-001
```

The collector requires Python 3 and curl. It makes only the scope-selected GET requests, with a maximum of six, including a benign control, unless a stop condition occurs. Normal input values are URL-encoded once. It does not implement crafted encoding differentials, authenticated testing, POST/JSON testing, DNS discovery, WAF vendor confirmation, or origin discovery. Run it against a disposable staging endpoint first. Arbitrary query probes cannot establish whether the application's actual routes are protected.

Exit 0 means collection completed, not that the target is secure. Exit 1 means collection stopped incomplete; exit 2 means invalid setup/input. Inspect `results.json` and the saved responses in every case. Response bodies are limited to 1 MiB; an oversized response fails collection rather than producing a success verdict. Evidence files use restrictive permissions and must still be reviewed/redacted before sharing.

The collector intentionally does not follow redirects, use an ambient proxy, load `.curlrc`, disable TLS validation, retry, or use out-of-band callbacks. If your approved environment requires a proxy or authentication, adapt and validate the collector before use. Interruptions can leave partial evidence without a final summary; treat such runs as incomplete.

## Detailed response analysis

New collector runs save full raw bodies and response headers, per-request response.json, response-text.txt, and curl-trace.txt. The curl trace records sent/received protocol diagnostics and ASCII data; the binary response body remains authoritative. Available curl JSON metrics include timing phases, negotiated HTTP version, connection addresses and TLS verification status. Older curl versions may provide only basic metrics.

Each evidence directory also includes analysis.json with consolidated requests/responses, analysis-report.md, untested-probe coverage and sha256-manifest.json. These are checkpointed after each completed request, so early stops retain useful analysis. A response is capped at 1 MiB and a failed transfer may be partial. Sensitive headers/cookies can appear in raw traces: retain originals locally and redact copies before sharing.

Runtime installation is complete in `../../pentest-tools/`; see [installation report](../../pentest-tools/INSTALLATION.md). The [installation plan](tool-install-plan.md) records the workflow. Pentest tools and containers have not been started; credentials and lab calibration remain pending.
