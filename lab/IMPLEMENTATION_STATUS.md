# AI Security Lab Implementation Status

Updated 3 October 2026. Version 0.1.0 is a local calibration harness with an authenticated application range and a separate WAF collector. The complete governed lab remains proposed.

## Record ownership fix

The authenticated application now requires record ownership in both profiles. Alice cannot read Bob’s record through the native API or synthetic AI retrieval. The vulnerable application profile retains three other seeded web defects. Historical four-defect receipts below describe the earlier code. In-process deterministic fixtures remain deliberate negative controls. The [ownership-fix receipt](verification/record-ownership-fix.json) records 27 passing tests and fresh authenticated pilot results.

## Current architecture

The [zoomable architecture document](../architecture/system-architecture.html) provides separate views for current implementation, WAF execution and future infrastructure. [Source evidence](../architecture/architecture-evidence.json) ties current components to code. The earlier `system-canvas.html` is superseded.

| Component | Actual execution boundary |
|---|---|
| `run-lab.sh` | Shell dispatcher to harness or WAF; does not start the pilot or range |
| `harness.py` | One Python process containing campaign logic, Broker, adapters, scoring and evidence writing |
| `fixtures.py` | Deterministic fixtures inside the harness process |
| `application_adapter.py` | In-process native request translation and synthetic bearer-session attachment |
| `application_server.py` | Separate HTTP process with SQLite state, sessions, audit records and optional local inference |
| `run_pilot.py` | Optional process that starts the range, calls harness functions, and checks saved state/audit effects |
| WAF collector | Separate scoped Python path that starts bounded curl subprocesses |
| Approval and evidence files | Operator-owned local files; no organizational approval service or protected collector |

Harness planning (`assist`) and target inference are different paths. The former uses Broker to save catalog selections for review. The latter is a direct application-to-model call with synthetic SQLite retrieval and mock tool effects. Neither implements the proposed management model broker.

## Implemented capabilities

- Standard-library Python harness in a uv environment, with 12 synthetic web/AI catalog cases and deterministic fixed/vulnerable fixtures.
- Manifest validation and local operator attestations bound to scope, source hash, purpose and expiry.
- Sequential execution, pacing, request budgets, absolute deadlines, numeric loopback restrictions, redirect denial and bounded responses.
- Strict scoring types, catalog-owned resource expectations and observable legitimate-task controls.
- Request/response evidence, replay, coverage reports, file hashes and chained events.
- Optional local planning contract accepting only approved catalog IDs.
- Authenticated native API adapter with private synthetic session files bound by hash.
- SQLite application range, persistent export/order state and application audit logs.
- Optional AI range inference, synthetic tenant retrieval, bounded mock actions and model/application logging.
- PyRIT seed export and schema validation, without evaluation execution.
- Separately scoped WAF collection requiring an explicit destination, expiring scope, permitted probes and limits.

## Recorded verification

These are saved verification results, not a new test execution for this documentation update.

| Check | Recorded result | Evidence |
|---|---|---|
| Regression suites | 40 passed: 21 harness/application tests and 19 WAF offline tests | [Review-fix receipt](verification/review-fixes.json), [test log](verification/review-fixes-tests.log) |
| Authenticated web pilot | Four seeded defects reproduced in the vulnerable range; zero reproduced failures in the fixed range; automated database/audit checks passed | [Pilot receipt](verification/review-fixes-pilot.json) |
| Actual AI model | Pending; transport contract tested with a mock endpoint | [Review-fix receipt](verification/review-fixes.json) |
| PyRIT bridge | Eight seeds accepted by installed 1.1.0 schema; no campaign executed | [Review-fix receipt](verification/review-fixes.json) |
| Independent human review | Pending | [Pilot acceptance](runs/pilot-chtilktx/acceptance.json) |
| Manual versus AI value | Not measured | [Pilot receipt](verification/review-fixes-pilot.json) |

`verification/validation.json` and `test-results.log` retain the earlier 17-test baseline. They are historical records; use the review-fix receipts above for the expanded implementation. Pilot results concern the supplied synthetic range, not a production application.

## Calibration follow-up

`run_calibration.py` adds up to three fresh runs per fixed/vulnerable AI profile, per-case consistency reporting, model/audit count checks and a pending human-review checklist. It reuses the pilot helper in-process; target applications remain separate subprocesses. `--prepare` writes the plan without model calls. Standard endpoints on ports 1234 and 11434 refused connections during this follow-up, so no actual-model calibration ran. See the [runbook](RUNBOOK.md) for commands and [follow-up receipt](verification/calibration-workflow.json) for verification.

## Remaining work and limits

- Actual local-model compatibility, security outcomes and legitimate task-quality calibration.
- Independent human verification, a manual baseline, review effort and total-cost measurement.
- Native Juice Shop and production adapters; the supplied range is a controlled benchmark.
- PyRIT target/executor/scorer integration and multi-turn campaigns.
- Hermes/OpenClaw execution through typed broker actions. Installed tooling is inventory, not integrated campaign execution.
- VM isolation, independent network controls and protected credential services.
- Authenticated organizational approvals, single-use capabilities and aggregate accounting across processes.
- Protected external evidence collection/checkpoints.
- Frontier provider integration, approved data release and aggregate spending enforcement.
- External asset testing and full OWASP coverage.

Application trace fields remain target-reported observations. The pilot inspects SQLite and audit files separately from harness response scoring, but all processes and files remain under the operator's access. A writable hash manifest is an integrity aid, not independent provenance. Local approvals can be reused before expiry. Harness loopback limits do not isolate the target's own outbound traffic or the host filesystem.

## Review fixes completed

Relocation was repaired; scoring rejects malformed types; resource expectations come from the catalog; legitimate AI controls require observable tasks; the native adapter uses synthetic authenticated sessions; and the pilot checks application state. WAF collection requires explicit, expiring scope. Documentation now separates in-process functions, separate target execution and undeployed infrastructure.
