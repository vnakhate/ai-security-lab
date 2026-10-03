# AI Security Lab

This project contains a local security calibration harness, an authenticated application range, a separately scoped WAF observation collector, architecture proposals, and installed research tools.

The project root is this directory. Harness source lives in `lab/`; installed tools live in `pentest-tools/`. Run these commands from the project root:

```sh
./lab/run-lab.sh doctor
./check.sh
./lab/.venv/bin/python lab/run_pilot.py
```

`check.sh` runs synthetic tests, including temporary loopback servers, and WAF offline checks. It contacts no external targets. If `.venv` is absent, use Python 3.12 or later or create it with `uv venv --python python3 lab/.venv`.

The pilot launches fresh authenticated local applications, runs vulnerable and fixed campaigns, verifies application database effects separately, and saves evidence under `lab/runs/pilot-*`. An expected vulnerable campaign exits 1; the pilot exits 0 only when its web acceptance checks succeed. Review `acceptance.json`, application audit logs, SQLite state, and the harness reports. Human independent review remains pending.

## Architecture and documentation

Explore the [test workflow across the physical lab](architecture/lab-workflow-on-hardware.html) on a zoomable Archify canvas. Machine boundaries and focused views connect the software steps to the proposed hardware.

The [physical lab plan](architecture/physical-lab-plan.html) and [software lab plan](architecture/software-lab-plan.html) describe the proposed dedicated setup, software roles, controls, and acceptance checks.

Open the [zoomable architecture document](architecture/system-architecture.html). It has separate views for [current processes](architecture/current-processes.html), the [WAF execution path](architecture/waf-processes.html), and the [proposed lab](architecture/proposed-system.html). [Source evidence](architecture/architecture-evidence.json) records the code behind the current view. The earlier `system-canvas.html` is superseded.

The current harness is one Python process: Broker, adapters, scoring and evidence writing run inside it. The optional application range is a separate Python HTTP process. The pilot calls harness functions in its own process and starts the range as a subprocess. Local approval and evidence files are operator-owned; there is no deployed organizational approval service or protected external collector.

There are two optional model paths. `assist` sends a planning request through the harness Broker and saves a suggestion for review. The AI range calls its configured local model directly for target inference. Neither path implements the proposed management model broker. WAF runs through its own scoped Python/curl path.

Use [implementation status](lab/IMPLEMENTATION_STATUS.md) for measured results, the [runbook](lab/RUNBOOK.md) for operation, and the [program proposal](ai-security-lab-proposal.md) for future governance and infrastructure.

## Current capabilities

- Twelve synthetic catalog cases with legitimate controls and attack replay.
- Approval binding to source, scope, purpose and expiry; bounded loopback HTTP transport.
- Strict scoring types and catalog-owned tenant/resource expectations.
- Authenticated native API adapter using private synthetic session files.
- SQLite application range with recorded exports, order state and audit events.
- Optional AI application integration with a local chat-completions model endpoint.
- WAF collector requiring explicit URL, expiring scope, permitted probes and limits.

Actual AI model quality, a manual versus AI value comparison, production adapters, VM isolation, organizational approval identities and protected external evidence storage remain unverified. The supplied application is a deliberately controlled benchmark, not evidence about a production application.

## Actual local-model campaign

Use an already running numeric-loopback model endpoint with the documented chat-completions contract:

```sh
./lab/.venv/bin/python lab/run_pilot.py \
  --model-url http://127.0.0.1:1234/v1/chat/completions --model YOUR_MODEL_ID
```

The application records actual model requests/responses and application audit events. Automated AI trace correlation does not replace an independent review. Contract tests use a mock model and do not establish model effectiveness. The local application supplies synthetic RAG documents and mock tool effects; it never executes model output as host commands.

For repeatable actual-model calibration, use `./lab/.venv/bin/python lab/run_calibration.py --prepare` to create a pending plan without model calls. Supply `--model-url` and `--model` to execute it. See the [runbook](lab/RUNBOOK.md) for limits, exit meanings and required human review.

## WAF scope

Offline validation is available without a target:

```sh
./lab/run-lab.sh waf --check-only
```

For authorized collection, first review and record the exact scope. This is a local operator attestation; obtain the actual asset owner's permission separately.

```sh
python3 lab/waf-assessment/scope.py \
  --target https://approved.example/api/search --parameter q \
  --owner ASSET_OWNER --approver AUTHORIZED_OPERATOR \
  --probes control xss --interval 10 --seconds 60 \
  --output lab/campaigns/waf-scope.json
./lab/run-lab.sh waf https://approved.example/api/search \
  --param q --interval 10 --scope lab/campaigns/waf-scope.json
```

Collection rejects changed destinations, parameters, code, pacing or expired scope. Application-harness approval files do not authorize WAF collection. There is no default external target.

## Installed tools after relocation

```sh
source ./pentest-tools/env.sh
```

The wrappers resolve their directory dynamically. Eight installed Python environments were repaired offline after the move. `pentest-tools/manifests/relocation.json` records the repair; original installation manifests and assessment evidence retain their historical paths. If the installation moves again, run `python3 pentest-tools/relocate.py` before using its Python environments. The repair does not download packages or launch scanners.

Read [harness instructions](lab/README.md), [adapter contracts](lab/ADAPTERS.md), [implementation status](lab/IMPLEMENTATION_STATUS.md), and the [program proposal](ai-security-lab-proposal.md).
