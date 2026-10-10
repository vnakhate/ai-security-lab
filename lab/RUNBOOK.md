# Pilot Campaign Runbook

Run one campaign at a time. The first campaign uses synthetic fixtures inside the Python process. It sends no network requests.

## Start from the project root

If your terminal prompt shows the project root, use:

```sh
cd /Users/venky/work/preprod/lab
./lab/run-lab.sh doctor
./lab/run-lab.sh waf --check-only
```

The WAF check sends no target requests. The launcher requires a command. Running `./lab/run-lab.sh` alone produces `the following arguments are required: command`.

If `./run-lab.sh` produces `no such file or directory` from project root, use `./lab/run-lab.sh` instead. The numbered campaign steps below first change into `lab/`; their remaining relative commands assume you stay there.

## 1 Inspect the runtime

```sh
cd /Users/venky/work/preprod/lab/lab
./run-lab.sh doctor
```

Read the reported isolation limits before continuing.

## 2 Create the conventional application campaign

```sh
./run-lab.sh init --track web --profile fixed --owner Venky --output campaigns/web-fixed.json
```

Inspect the manifest:

```sh
cat campaigns/web-fixed.json
```

The default limits allow 100 requests, 900 seconds and one request each second. Each case needs three requests per repeat. Four web cases with three repeats require 36 requests.

## 3 Validate the scope

```sh
./run-lab.sh validate --manifest campaigns/web-fixed.json
```

Validation sends no requests.

## 4 Record your local approval

```sh
./run-lab.sh approve --manifest campaigns/web-fixed.json --approval campaigns/web-fixed.approval.json --approver Venky --minutes 60
```

This command records your attestation. It does not obtain another person's consent. For organizational tests, obtain the actual asset approval separately.

## 5 Execute the fixed controls

```sh
./run-lab.sh run --manifest campaigns/web-fixed.json --approval campaigns/web-fixed.approval.json --repeats 3
```

The command prints the unique evidence directory. The fixed fixture should produce `observed_control_pass` for all selected cases.

Read `REPORT.md`, `summary.json`, `coverage.json` and `events.jsonl` in that directory. Replace the path below with the printed directory:

```sh
./run-lab.sh verify runs/REPLACE_WITH_PRINTED_DIRECTORY
```

## 6 Calibrate detection with the vulnerable fixture

```sh
./run-lab.sh init --track web --profile vulnerable --owner Venky --output campaigns/web-vulnerable.json
```

Inspect and validate the new manifest. Record a new approval:

```sh
./run-lab.sh validate --manifest campaigns/web-vulnerable.json
./run-lab.sh approve --manifest campaigns/web-vulnerable.json --approval campaigns/web-vulnerable.approval.json --approver Venky
./run-lab.sh run --manifest campaigns/web-vulnerable.json --approval campaigns/web-vulnerable.approval.json --repeats 3
```

The vulnerable fixture should produce four reproduced failures per repeat. Exit code `1` is expected. It indicates detected fixture failures.

## 7 Run the AI fixture campaign

```sh
./run-lab.sh init --track ai --profile fixed --owner Venky --output campaigns/ai-fixed.json
./run-lab.sh validate --manifest campaigns/ai-fixed.json
./run-lab.sh approve --manifest campaigns/ai-fixed.json --approval campaigns/ai-fixed.approval.json --approver Venky
./run-lab.sh run --manifest campaigns/ai-fixed.json --approval campaigns/ai-fixed.approval.json --repeats 3
```

Eight AI cases with three repeats require 72 requests. These fixtures simulate AI application behavior. They do not load or call a language model.

Create a separate `ai-vulnerable.json` manifest with `--profile vulnerable` when you want to calibrate the AI failure oracles. Review and approve it before running it. Eight reproduced failures per repeat and exit code `1` are expected.

Do not combine all 12 cases with three repeats under the default 100-request cap. That combination requires 108 requests. The harness rejects it before execution.

## 8 Test the HTTP adapter with local fixtures

In a separate terminal, start the fixed fixture server:

```sh
cd /Users/venky/work/preprod/lab/lab
.venv/bin/python fixture_server.py --profile fixed --port 8765
```

Create a new campaign manifest. Replace its target object with:

```json
{"adapter": "http", "url": "http://127.0.0.1:8765"}
```

Retain only the required catalog test IDs. Validate the manifest. Record a fresh approval. Run the campaign through the same launcher.

The server listens only on loopback. Ctrl+C stops it. Each request is stateless. The harness does not start or stop this server for you.

Connecting Juice Shop or another application requires an application-specific adapter. The reference routes do not match Juice Shop's native API. Follow `ADAPTERS.md` before changing the target.

## 9 Add local model assistance

Use an existing local model server with the documented chat-completions contract. The harness does not install or start a model server.

Add this planner object to a new manifest. Use your actual local endpoint and model ID:

```json
"planner": {
  "url": "http://127.0.0.1:1234/v1/chat/completions",
  "model": "YOUR_LOCAL_MODEL_ID"
}
```

Validate the manifest. Record approval for planning:

```sh
./run-lab.sh approve --manifest campaigns/ai-assisted.json --approval campaigns/ai-assisted.plan-approval.json --approver Venky --purpose assist
./run-lab.sh assist --manifest campaigns/ai-assisted.json --approval campaigns/ai-assisted.plan-approval.json
```

Read the saved `suggestion.json`. It contains catalog test IDs and a rationale. Review it before editing the manifest's test selection. After any edit, validate and approve the manifest again for `run`.

The planning approval cannot authorize a campaign run. The model cannot introduce new test IDs, tools or target destinations.

## 10 Export AI cases for PyRIT

```sh
./run-lab.sh export-pyrit --manifest campaigns/ai-fixed.json --output campaigns/pyrit-seeds.json
```

This command exports data only. It does not run PyRIT. The seed values contain JSON application requests rather than standalone prompts.

Use the existing PyRIT Python environment to run `pyrit_import_check.py` against the dataset if required. That script validates the dataset schema. It sends no target requests.

The existing workspace environment is:

```sh
/Users/venky/work/preprod/lab/pentest-tools/repos/pyrit/.venv/bin/python pyrit_import_check.py campaigns/pyrit-seeds.json
```

## Authenticated application pilot

The fixture steps above calibrate deterministic oracles. To test native sessions and persistent application effects, run the separate pilot from the project root:

```sh
cd /Users/venky/work/preprod/lab
./lab/.venv/bin/python lab/run_pilot.py
```

The pilot starts fresh fixed and vulnerable SQLite range processes, prepares synthetic session-bound manifests and local attestations, calls the harness campaign in the pilot process, and checks database/audit effects. `run-lab.sh` does not start this pilot or the range. The web pilot exits 0 only when its automated acceptance checks pass; reproduced vulnerable fixture failures are expected.

Inspect the printed pilot directory's `acceptance.json`, each profile's `acceptance.json`, `checkpoint.json`, application audit records and campaign reports. Checkpoints are operator-owned integrity records. Human review and separately protected provenance remain pending.

For the optional AI range, supply an already running local model endpoint:

```sh
./lab/.venv/bin/python lab/run_pilot.py \
  --model-url http://127.0.0.1:1234/v1/chat/completions --model YOUR_MODEL_ID
```

This invokes target inference from the application process; it is separate from the `assist` workflow in step 9. The model receives synthetic SQLite retrieval and uses bounded mock tool effects. Inspect model logs and application audit evidence alongside the harness results. The pilot's AI output does not establish model effectiveness or complete a human review. Mock endpoint contract tests do not establish actual-model calibration.

See [implementation status](IMPLEMENTATION_STATUS.md) and the [current process canvas](../architecture/current-processes.html) for the evidence and process boundaries.

## Repeatable actual-model calibration

Prepare a three-run-per-profile plan without model calls:

```sh
cd /Users/venky/work/preprod/lab
./lab/.venv/bin/python lab/run_calibration.py --prepare
```

Once a local endpoint and model ID are available:

```sh
./lab/.venv/bin/python lab/run_calibration.py \
  --model-url http://127.0.0.1:1234/v1/chat/completions --model YOUR_MODEL_ID
```

The runner calls the pilot helper inside its own process and starts fresh application subprocesses for each profile/repetition. Default calibration plans 144 application requests across six campaigns. Each campaign retains the pilot's 100-request and 900-second limits. `--repeats` permits 1, 2 or 3. Model logs must match application requests and audit counts. Results aggregate each case across fresh runs; vulnerable-profile failures are observations rather than a required real-model outcome.

Exit 0 requires complete, conclusive, consistent observations with no reproduced fixed-profile failure. Exit 1 records consistent fixed-profile failures. Exit 2 means incomplete, inconclusive or inconsistent results. None grants human security acceptance. Inspect `calibration.json` and complete `REVIEW.md`; manual comparison remains unmeasured. The wrapper shares the operator access boundary and does not add a model broker or OS isolation.

## Stop and recovery

Ctrl+C stops a foreground campaign. Partial evidence remains available.

To request a stop from another terminal, create a file named `STOP` inside the current run directory. The broker checks this file before requests, during pacing and between response reads.

```sh
touch runs/REPLACE_WITH_CURRENT_RUN_DIRECTORY/STOP
```

A pending socket operation can delay recognition until its timeout. The default timeout is 10 seconds. The stop file does not revoke credentials or terminate a separate target server.

Redirects, HTTP 429, server errors, an invalid benign baseline, expired approval and exhausted limits stop the campaign. Preserve evidence. Resolve the cause before creating a new run. The harness does not resume partial campaigns.

## Reset and retest

Built-in fixtures reset before each case and replay. A custom HTTP target must provide an independently operated reset process. The harness does not assume that a remote target resets.

After a fix, use the same case definitions and a reset target. Record the new application revision. Review the observed behavior independently before closing a finding.

## WAF assessment module

The WAF collector is a separate module within this lab. Read its [engagement playbook](waf-assessment/akamai-waf-pentest-playbook.md) before collection.

Run offline validation from the lab directory:

```sh
cd /Users/venky/work/preprod/lab/lab
./run-lab.sh waf --check-only
```

This command sends no target requests. WAF runs retain their own authorization requirements and baseline safety stop. Approval for an application/AI harness campaign does not grant approval for a WAF target.

## Isolation substrate (U2)

Real targets (a web app under test, a tool-calling agent, an MCP server) and any outward probing run confined, not in the harness process. The harness core and the tamper-evident evidence stay on the host; the target runs as a non-root, read-only, capability-dropped container with resource limits, attached only to a Docker `--internal` network. That network has no route off itself, so the target reaches the out-of-band sink and the co-located target on the same network and nothing else — no internet egress.

`lab/isolation.py` builds and validates the invocation:

- `build_network_argv(name)` creates the `--internal` network.
- `build_run_argv(spec)` builds the hardened `docker run` (non-root user, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, `--pids-limit`/`--memory`/`--cpus`, a single writable `/work` mount).
- `validate_run_argv(argv)` refuses a root user, host network, `--privileged`, or a docker-socket mount.
- `require_isolation()` fails closed: with no reachable Docker daemon it raises rather than let a real target run unconfined.

Verify the live boundary once per machine (manual smoke check, not in `check.sh`):

```sh
docker network create --internal lab-oob-smoke
# a container on an --internal network cannot reach the internet:
docker run --rm --network lab-oob-smoke --user 65534:65534 --read-only \
  --cap-drop ALL --security-opt no-new-privileges alpine \
  sh -c 'wget -T3 -q -O- https://example.com || echo EGRESS_BLOCKED_OK'
docker network rm lab-oob-smoke
```

Limits: this is process/namespace isolation via Docker, not a defense against kernel or hypervisor exploits. On macOS, Docker runs in its own VM, which adds a boundary but is not a substitute for a dedicated air-gapped host when a target is genuinely untrusted. Evidence integrity still depends on the host-side `verify()`; the target never gets write access to `lab/runs/`.
