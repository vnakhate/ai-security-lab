# AI Security Lab External Reviewer Guide

Updated 5 October 2026. Audience: an independent reviewer of this repository.

## Purpose and review conclusion

This repository contains a local security test prototype and a proposed operational lab for two operators. It is not a deployed testing platform.

Review the implemented code separately from the proposed architecture. Determine whether the local controls work, whether the evidence supports the recorded results, and what must change before external testing.

The intended operational scope has three profiles:

1. Web application and API testing through an approved WAF.
2. AI application testing when the approved target includes an AI feature.
3. AI agent testing when the approved target includes an agent that uses tools.

The review should produce findings, evidence gaps, and an implementation readiness decision. A completed local suite does not establish the security of an external application.

## Repository snapshot

The repository root is `/Users/venky/work/preprod/lab` on the development machine. A reviewer can use a different checkout location.

The baseline inspected for this guide is `dbfbca9`. The three-profile document update, expanded explainer, and testing presentation follow that baseline. Record the actual reviewed commit and any uncommitted changes in the review report.

Git excludes downloaded tools, Python environments, runtime campaigns, and most raw run evidence. A clean checkout will not contain the development machine's installed environments or private campaigns.

Do not infer installation or execution from a repository manifest alone. Historical evidence can contain paths from an earlier checkout.

## Reading order

| Read | Purpose |
|---|---|
| [Project README](../README.md) | Entry points and repository layout |
| [Implementation status](../lab/IMPLEMENTATION_STATUS.md) | Current behavior, recorded results, and known limits |
| [Current process diagram](../architecture/current-processes.html) | Actual process boundaries |
| [Adapter contracts](../lab/ADAPTERS.md) | Supported target and model contracts |
| [OWASP integration document](OWASP_TOOL_INTEGRATION.md) | Three assessment profiles, tool assignments, and required evidence |
| [Implementation plan](IMPLEMENTATION_PLAN.md) | Proposed build order and acceptance checks |
| [Consolidated architecture](../architecture/consolidated-lab-architecture.html) | Proposed operational deployment |
| [Testing presentation](../presentations/output/web-app-ai-agent-testing.pptx) | Summary of web, AI application, and AI agent testing |

Treat source code as the authority for implemented behavior. Treat diagrams and presentations as explanations. Report any disagreement.

## Implemented and proposed components

| Component | Current position | Review implication |
|---|---|---|
| Application/AI harness | Python process with validation, Broker, adapters, scoring, and evidence writing | Internal functions are not independent security services |
| Synthetic fixtures | Deterministic cases inside the harness process | These check harness behavior, not actual model security |
| Authenticated application range | Separate HTTP process with SQLite, synthetic sessions, and audit records | This is a controlled benchmark, not a production application |
| Optional target inference | Application calls a configured local model directly | This does not implement the proposed host model access service |
| WAF collector | Separate scoped Python/curl path | Supports limited unauthenticated GET-query observations |
| PyRIT bridge | Seed export and import checks | Does not execute PyRIT evaluations |
| Tool inventory | Supplied repository records and local installation information | Most tools lack accepted campaign adapters |
| Dashboard, shared engine, and run index | Proposed | No operational UI/CLI orchestration acceptance exists |
| Runner VM and network controls | Proposed | Current loopback checks do not provide OS isolation |
| External model adapter | Proposed | Provider contract and data approval remain unresolved |

The SQLite database in the application range stores target state. It is separate from the proposed SQLite index for campaign records.

## Code inspection map

| Source | Review focus |
|---|---|
| [check.sh](../check.sh) | Test discovery, interpreter selection, and shell checks |
| [run-lab.sh](../lab/run-lab.sh) | Dispatcher and interpreter fallback |
| [harness.py](../lab/harness.py) | Manifest validation, approval binding, Broker restrictions, scoring, stopping, and evidence |
| [catalog.py](../lab/catalog.py) and [fixtures.py](../lab/fixtures.py) | Case definitions, expected results, controls, and seeded failures |
| [application_adapter.py](../lab/application_adapter.py) | Session validation and native request translation |
| [application_server.py](../lab/application_server.py) | Record ownership, role checks, target state, retrieval, and model calls |
| [run_pilot.py](../lab/run_pilot.py) | Fresh target processes and independent state/audit checks within the operator boundary |
| [run_calibration.py](../lab/run_calibration.py) | Repetition, consistency checks, and pending human review |
| [scope.py](../lab/waf-assessment/scope.py) | Exact scope, expiry, source binding, and request accounting |
| [waf_check.py](../lab/waf-assessment/waf_check.py) | Curl execution, response limits, classification, and retained output |
| [Tool registry](../pentest-tools/manifests/lab-tool-coverage.json) | Pinned sources, intended roles, readiness, and exclusions |

## Review the three test profiles

### Web application and API testing

Check ownership and role enforcement with separate synthetic accounts. Alice must read her own record. The application must deny her access to Bob's record.

Compare permitted actions with forbidden actions. Inspect state changes and audit records rather than relying only on status codes.

The WAF collector does not support authentication, POST/JSON bodies, or complete browser workflows. Those tests need additional accepted adapters.

A WAF block does not prove that the application safely processes input. A successful response does not prove a vulnerability.

### AI application testing

Distinguish deterministic fixtures, mock transport checks, and actual model execution. Only actual model execution can supply observations about that model.

Review retrieval isolation, protected synthetic data, output handling, and resource limits. Check downstream effects in addition to model responses.

An assistant model that explains web evidence is not the AI application under test. Review its data access and advice separately.

### AI agent testing

Distinguish a lab assistant from an agent in the target application. Testing lab controls does not establish the security of an external agent.

Check agent identity, tool permissions, approval rules, and actual execution effects. Include hostile documents and tool responses that request actions outside scope.

Check whether changed action parameters invalidate approval. Check whether stop controls prevent new actions. Preserve partial evidence.

The synthetic range uses mock tool effects. It does not demonstrate containment of an arbitrary autonomous agent or host command execution.

## Recorded evidence

The following files contain historical verification. No new suite or campaign ran to create this guide.

| Evidence | Recorded result | Limit |
|---|---|---|
| [Ownership fix](../lab/verification/record-ownership-fix.json) | 27 regression tests and authenticated local checks. Both profiles return 200 for the owner's record and 403 for Bob's record. | Synthetic localhost target. AI retrieval uses a mock. Human review remains pending. |
| [Review fixes](../lab/verification/review-fixes.json) | Expanded harness and WAF offline verification | Predates the ownership correction. Read with the later receipt. |
| [Earlier pilot](../lab/verification/review-fixes-pilot.json) | Earlier fixed/vulnerable range observations | Four-defect results are historical. The vulnerable application now retains three seeded web defects. |
| [Calibration workflow](../lab/verification/calibration-workflow.json) | 45 recorded regression tests passed | Actual model execution did not run. Local endpoints refused connections. |
| [Relocation receipt](../lab/verification/waf-relocation.json) | WAF package relocation records | File relocation does not establish assessment results |

Counts describe separate verification snapshots. Do not add them together as unique tests.

Some receipts reference ignored `lab/runs/` files. Request a reviewed synthetic evidence package if the review needs those files. A JSON receipt alone cannot replace the underlying evidence.

## Local reproduction

Use Python 3.12 or later. Read [the runbook](../lab/RUNBOOK.md) before creating a campaign.

From the repository root:

```sh
./lab/run-lab.sh doctor
./check.sh
```

`doctor` reports runtime information. `check.sh` runs the harness tests, WAF offline tests, and shell syntax checks. Tests use temporary loopback servers. They do not assess external targets.

`check.sh` prefers `lab/.venv/bin/python` and otherwise uses `python3`. Check the selected interpreter before comparing results.

For WAF offline checks alone:

```sh
./lab/run-lab.sh waf --check-only
```

For a fresh authenticated synthetic pilot:

```sh
python3 lab/run_pilot.py
```

The pilot creates local target processes and evidence under `lab/runs/pilot-*`. It checks application state and audit effects. Expected failures in the vulnerable profile are test observations.

Inspect `acceptance.json`, profile reports, application audit records, SQLite state, and checkpoints. Compare the pilot's final acceptance result with the campaign outcomes.

Record the command, interpreter version, code revision, exit status, and evidence directory. Do not compare exit codes across modules without reading their documented meanings.

## Security boundaries and known limits

- Local approval files record operator attestations. They do not authenticate organizational approval identities.
- The operator can change evidence files and their hashes. Hash checks do not provide independent provenance.
- Numeric loopback restrictions limit harness destinations. They do not isolate the host filesystem or the target's outbound traffic.
- Current stopping behavior differs from the proposed engine's full process-tree controls. Review the implemented path before claiming stop effectiveness.
- Harness approval does not authorize WAF collection. The WAF path has its own scope contract.
- Installed tools do not establish provider compatibility, enforced request accounting, or safe agent execution.
- OWASP mappings identify proposed objectives. They do not establish complete coverage or certify tools.

## External execution prerequisites

External assessment is a separate activity. This reviewer guide does not authorize target traffic.

Before an external campaign, require owner authorization, exact destinations, routes, methods, inputs, accounts, expiry, shared limits, and a stop contact.

Require accepted adapters and independently checked runner/network restrictions. Check WAF and application log access. Resolve a blocked normal baseline with the owner before further testing.

Before external model calls, check the exact endpoint, model ID, provider terms, allowed data, and cost limits. The operator's proposed Grok 3.7 Cyber endpoint remains unconfirmed.

Use synthetic data for local reproduction. Review and redact copies of evidence before external sharing. Preserve original evidence in restricted storage.

## Reviewer report

Record these fields for each finding:

- Reviewed commit and working-tree changes.
- Source file or design requirement.
- Reproduction steps and prerequisites.
- Expected and observed behavior.
- Evidence references and execution boundary.
- Impact, priority, and recommended correction.
- Retest result or remaining evidence gap.

Separate code defects, design gaps, documentation errors, and missing operational evidence.

Conclude separately on local prototype behavior, operational lab readiness, and external assessment readiness. List the conditions for each decision.

## Review completion checks

1. Reconcile implemented behavior with the current process diagram.
2. Reproduce relevant local tests and inspect their evidence.
3. Check ownership, scope binding, scoring, stopping, and evidence handling.
4. Identify missing access, instrumentation, adapters, and isolation.
5. Review the web, AI application, and AI agent profiles separately.
6. Issue an evidence-backed report with unresolved conditions.

An acceptable prototype review can still leave operational deployment and external assessment unapproved.
