# AI Security Lab Harness

The lab contains two execution modules: this application/AI harness and the [WAF assessment module](waf-assessment/README.md). Shared installed tools remain in `../pentest-tools/`.

Use `./run-lab.sh waf --check-only` for offline WAF validation. The WAF module retains its own scope, pacing, baseline stop rules and evidence format. Harness approval files do not authorize WAF collection. Explicit WAF collection can contact an authorized external endpoint; the application/AI harness remains limited to loopback targets.

WAF evidence is stored in `lab/waf-assessment/runs/` and `lab/waf-assessment/results/`. Existing evidence retains its original recorded paths and bytes. [Relocation receipt](verification/waf-relocation.json) records the old and new roots and evidence hashes.

This harness runs synthetic application and AI application campaigns. It provides approved scope, bounded execution, raw evidence and deterministic replay.

The first version contains 12 test cases:

- Four application cases: object access, role access, business workflow and exceptional conditions.
- Eight AI cases: injection, disclosure, tool approval, retrieval, hidden context, consumption, output handling and misinformation.

Each case includes a legitimate control, an adversarial request and an attack replay. OWASP coverage identifies selected cases and untested categories.

The built-in targets are deterministic simulators. They calibrate the harness. They do not measure an actual language model's security.

## Process architecture

The [architecture document](../architecture/system-architecture.html) separates [current processes](../architecture/current-processes.html), [WAF execution](../architecture/waf-processes.html) and the [proposed infrastructure](../architecture/proposed-system.html).

The launcher selects one execution path. Harness campaign orchestration, Broker, adapters, scoring and evidence writing share a Python process. Built-in fixtures run inside it. The authenticated SQLite range is a separate HTTP process; its native adapter is a function in the harness, not a gateway service. The optional pilot starts that range and calls harness functions directly in the pilot process.

Harness `assist` calls a planning endpoint through Broker and saves a suggestion. Target `/api/ai/chat` calls the range's configured model directly. Retrieval uses synthetic SQLite documents; tool effects are mocked. Local approval files do not authenticate an organizational approver, and evidence files are not protected from the operator who owns them.

## Start here

From the project root (`/Users/venky/work/preprod/lab`), run:

```sh
cd /Users/venky/work/preprod/lab
./lab/run-lab.sh doctor
./lab/run-lab.sh waf --check-only
```

`doctor` displays runtime information. `waf --check-only` runs offline validation and sends no target requests. The launcher requires a command; `./lab/run-lab.sh` alone prints a usage error. Use `./lab/run-lab.sh --help` to list harness commands, or `./lab/run-lab.sh waf --help` for WAF options.

Use the launcher path that matches your current directory:

| Current directory | Runtime information | WAF offline checks |
|---|---|---|
| project root | `./lab/run-lab.sh doctor` | `./lab/run-lab.sh waf --check-only` |
| `lab/` | `./run-lab.sh doctor` | `./run-lab.sh waf --check-only` |

The isolated uv environment is prepared at `lab/.venv`. The launcher uses that environment.

```sh
cd /Users/venky/work/preprod/lab/lab
./run-lab.sh doctor
```

Follow [RUNBOOK.md](RUNBOOK.md) for one campaign at a time. Read [ADAPTERS.md](ADAPTERS.md) before connecting an application or local model.

## Commands

| Command | Result |
|---|---|
| `doctor` | Show runtime and implementation limits. No target requests. |
| `catalog` | Show test objectives, requests, oracles and OWASP identifiers. |
| `init` | Create a campaign manifest. Existing manifests are not overwritten. |
| `validate` | Check manifest fields and limits. No target requests. |
| `approve` | Record a local operator attestation bound to scope, code, purpose and expiry. |
| `run` | Execute controls, attacks and replay. Save evidence and coverage. |
| `assist` | Ask an approved loopback model endpoint to select existing test IDs. Save a suggestion for human review. |
| `export-pyrit` | Export AI cases as a PyRIT seed dataset. No PyRIT execution. |
| `verify` | Check saved file hashes and the event chain. |

## Evidence

Each run uses a unique directory under `lab/runs` unless another output root is supplied.

| Artifact | Content |
|---|---|
| `scope.json` | Exact campaign manifest. |
| `approval.json` | Local approval record used for the run. |
| `catalog.json` | Selected test definitions and oracles. |
| `events.jsonl` | UTC events, exact request bodies, response status/headers, raw response bytes and results. |
| `summary.json` | Completion state, errors, repeats, results and source hash. |
| `coverage.json` | OWASP category mapping, planned tests and observed outcomes. |
| `REPORT.md` | Human-readable campaign report. |
| `sha256.json` | File hashes for integrity checking. |

Response records contain both base64 bytes and a UTF-8 rendering. Oversized responses retain a bounded prefix and stop the run as incomplete. Responses are not silently truncated and scored.

Files use private permissions when the launcher runs. Raw evidence can still contain sensitive information from a misconfigured local application. Use synthetic data only. Restrict the evidence directory. Review and redact evidence before sharing it.

## Outcome meanings

- `observed_control_pass`: both attack attempts satisfied the deterministic oracle for the tested condition.
- `reproduced_failure`: both attack attempts produced the defined failure.
- `inconclusive`: instrumentation was absent, malformed or inconsistent between attempts.

Replay uses the same harness and target. It does not replace independent human verification. The report explicitly records human review as pending.

Exit code `0` means the campaign completed and its selected cases passed. Exit code `1` means a completed campaign contains failures or inconclusive cases. Exit code `2` means validation failed or execution stopped incomplete. Ctrl+C returns `130` and preserves partial evidence.

## Enforcement and limits

The harness enforces numeric loopback destinations, explicit ports, catalog paths, POST requests, sequential execution, pacing, request counts, time limits and response-size limits. It does not follow redirects, use environment proxies, retry requests or execute shell commands.

The local model can select existing approved cases. It cannot generate executable commands or add destinations. A suggestion does not execute tests.

The approval file is an operator attestation. It does not authenticate the approver or provide a signed organizational approval service. Approvals can be reused before expiry within this local pilot. They do not implement single-use capabilities or cross-process spending accounting.

Hash manifests and chained events detect changes against the retained hashes. A person with write access can replace both evidence and hashes. Copy the final checkpoint to separately protected storage when independent provenance matters.

This process is not a VM or an OS security sandbox. It does not provide filesystem, credential or kernel isolation against a compromised process. External targets, frontier providers, arbitrary scanners, Hermes execution and OpenClaw execution remain outside this version.

PyRIT export is a dataset bridge. PyRIT attacks, model scorers and multi-turn orchestration are not automatically invoked. See the adapter guide for the integration boundary.

## Verification

```sh
cd /Users/venky/work/preprod/lab/lab
.venv/bin/python -m unittest discover -s tests -v
```

The suite uses in-process fixtures and temporary loopback servers. It does not start installed pentesting tools, Docker workloads or external assessments.

To rebuild the Python environment on another machine:

```sh
uv venv --python python3 .venv
```

Python 3.12 or later is required. The harness uses only the standard library.
