# Minimal AI Security Lab Implementation Plan

Date: 4 October 2026
Status: proposed implementation plan. No implementation starts with this document.

## Outcome

Build a lab that two operators can manage. Use one private dashboard and CLI to control the same campaigns.

The lab must meet two separate acceptance goals:

1. Calibrate local models and tool adapters on synthetic targets with known outcomes.
2. Assess an approved external corporate website through its WAF and produce reviewed evidence.

A passing local calibration does not complete the external assessment. A completed campaign does not establish that a target is secure.

The [current requirements](../ai-security-lab-proposal.md) and [consolidated architecture](../architecture/consolidated-lab-architecture.html) define the design. This plan implements the minimal requirements section. The larger historical proposal is a future option.

## Starting point

The repository contains a local application harness, synthetic range, and a separate scoped WAF collector. It also contains tool sources, saved verification records, architecture documents, and a presentation.

The dashboard, shared engine, run index database, isolated runner, and model access service remain proposed. Existing application SQLite databases are target fixtures. They are not the proposed campaign run index.

The WAF collector supports bounded unauthenticated GET requests with query inputs. Authentication, POST bodies, and browser workflows need additional accepted adapters.

No live endpoint or provider calls form part of this planning task.

## Minimal implementation choices

| Area | Initial choice | Expansion trigger |
|---|---|---|
| Control service | One Python service that reuses existing Python code | Measured limitations justify a change |
| Dashboard | HTML with limited JavaScript, served by the control service | A concrete workflow needs more UI behavior |
| CLI | Thin client of the same service API | No separate execution engine |
| Run index | SQLite with migrations and one service owning writes | Measured concurrency or recovery needs exceed SQLite |
| Evidence | Restricted folders outside the source checkout | Storage volume or required provenance needs change |
| Scheduling | One active campaign and one runner | Sustained demand justifies parallel campaigns |
| Execution | Disposable Linux runner VM | An accepted tool needs a different isolated environment |
| Local models | One inference service on the dedicated lab computer | Resource pressure or required isolation justifies a GPU host |
| External models | One accepted provider adapter | Another model passes compatibility and data checks |
| Reports | JSON and readable HTML with evidence links | A required export format justifies another renderer |

The Mac remains an administration client. Development can use local synthetic tests before dedicated hardware exists. Local development does not demonstrate VM isolation.

Use two named accounts. Record who prepares, approves, runs, stops, and reviews a campaign. Choose the authentication mechanism in Phase 0.

## Build order and dependencies

| Phase | Deliverable | Depends on | Completion check |
|---|---|---|---|
| 0 | Contracts and fixtures | Current requirements | Valid synthetic campaign and documented schema |
| 1 | Run index, evidence store, read-only dashboard | Phase 0 | UI and CLI show identical imported records |
| 2 | Shared engine and first collector adapter | Phase 1 | UI start, CLI inspect, shared stop, retained evidence |
| 3 | Runner VM and network controls | Phase 2 and selected hardware | Escape, egress, and stop checks pass |
| 4 | Applicable deterministic tool adapters | Phase 3 | Seeded checks and budget enforcement pass |
| 5 | Local model access and calibration | Phase 3 and available model hardware | Local model passes role-specific calibration |
| 6 | External model adapter | Phase 5 and provider contract | Data release and usage limits pass synthetic tests |
| 7 | Corporate WAF pilot and coverage expansion | Phases 4 and 3, target details and approval | Owner-correlated evidence and human review |

Phase 7 can assess the WAF without an AI provider. An AI-assisted assessment additionally requires accepted model and tool integrations.

Phases 4 and 5 can progress independently after isolation passes. Implement one adapter at a time so failures remain easy to diagnose.

See the [OWASP tool integration mapping](OWASP_TOOL_INTEGRATION.md) for adapter assignments and evidence requirements.

## Phase 0: contracts and fixtures

Define these contracts before writing the dashboard or engine:

- Campaign configuration: exact destinations, routes, methods, inputs, account roles, expiry, actions, and limits.
- Scope review: reviewer identity and the hash of the approved configuration.
- Tool plan: version, adapter, arguments, disposition, prerequisites, and reason for exclusion.
- Model policy: local-only or approved-external mode, exact model, allowed data, timeout, and cost limit.
- Run state: prepared, approved, checking, running, stopping, stopped, failed, completed, and reviewed.
- Evidence metadata: producing step, timestamp, relative path, size, hash, and sensitivity classification.

Approval binds the exact configuration. Editing scope or the tool plan invalidates approval. Reviewed describes a human review, not a vulnerability score.

Create synthetic success, blocked-baseline, failed-tool, stopped-run, and interrupted-service examples. Mark example data visibly. Do not populate a real scope with placeholder destinations.

Acceptance: validation rejects expired scope, unsupported methods, missing dispositions, unsafe paths, and changed approvals. Synthetic cases require no external requests.

## Phase 1: run index and read-only dashboard

Create SQLite tables for runs, steps, approvals, tool dispositions, artifact references, model calls, and review decisions. Record schema versions and migration history.

Keep large artifacts in restricted folders. SQLite stores their metadata and links. Resolve evidence paths under the storage root and deny traversal.

Import existing receipts through an explicit importer. Preserve original files and provenance. Imported runs must retain their historical execution limits.

The dashboard shows run history, state, stop reason, step outcomes, coverage gaps, and evidence links. The CLI lists runs and displays the same details.

Acceptance: both interfaces show identical run IDs and state. Missing or damaged artifacts appear as errors. The dashboard escapes untrusted tool output and exposes no source secrets.

First usable milestone: operators can inspect existing and synthetic runs. Execution controls remain unavailable until Phase 2 passes.

## Phase 2: shared engine and collector adapter

Expose preparation, review, start, status, stop, and export through one service API. The CLI and UI call that API.

Use fixed adapter contracts with allowlisted arguments. Never accept arbitrary shell commands from forms or model output.

Integrate the existing WAF collector without weakening its scope checks. Start with synthetic local targets and its supported GET-query contract.

The engine enforces one active campaign, total request budget, pacing, deadline, and process limits. Each adapter reports actual requests and outcomes.

Stop blocks new work and terminates the full process tree. Preserve partial outputs and the stop reason. Stop cannot reverse requests already sent.

On restart, reconcile an interrupted run with worker state. Never silently resume or duplicate requests. Mark uncertain execution as interrupted and require a fresh reviewed run.

Acceptance: start through the UI, inspect through the CLI, and stop through either. Both interfaces recover the same evidence. Test competing starts, repeated stop calls, crash recovery, and stale approval.

This milestone establishes engine behavior on local synthetic targets. External execution waits for Phase 3.

## Phase 3: runner isolation and deployment

Select the dedicated host OS and hypervisor before preparing the VM package. Record the selected versions and resource limits.

Create a disposable runner image and an authenticated private control channel. Limit execution to accepted adapters and approved campaign inputs.

The VM receives no host folders, provider keys, personal credentials, management access, or host Docker socket. Use limited test credentials only when the campaign requires them.

Enforce runner egress outside agent prompts. Allow approved target traffic and the controlled model relay. Account for DNS and shared CDN addresses. IP allowlists alone cannot enforce hostname, route, or method scope.

Validate application scope in adapters. Block an adapter if the required scope or request accounting cannot be enforced.

The host service copies new artifacts from the runner into restricted storage. Deny runner access to historical evidence. The private dashboard uses named accounts and authenticated connections.

Back up SQLite consistently with its journal state and copy referenced evidence. Restore both stores in a recovery test. A writable hash file does not provide independent provenance.

Acceptance: deny an unapproved destination, host file access, provider key access, and historical evidence modification. Verify process-tree stop and a clean VM reset.

## Phase 4: deterministic tool adapters

Use the [tool coverage registry](../pentest-tools/manifests/lab-tool-coverage.json) as the inventory. Include all supplied repositories and additional tools in each campaign plan.

Evaluate WAF fingerprinting and scoped HTTP checks first. Add selected vulnerability checks when scope and adapters support them. Use source tools only when approved source exists.

Method repositories supply reviewed procedures and cases. AI evaluators require an AI target. Origin discovery and additional assets require explicit scope.

Every tool receives selected, blocked, deferred, or not applicable status with a reason. A comprehensive profile runs every applicable calibrated adapter within the shared limits.

Acceptance: a selected adapter detects expected synthetic failures, respects redirects and scope, preserves raw output, and stops correctly. A failed tool remains visible in the report.

## Phase 5: local models

Add model access inside the host service. Implement one local runtime adapter and a bounded relay for accepted runner tools.

Record the model source, license, weight hash, quantization, runtime version, memory needs, and accepted roles. Measure context limits and structured-output compatibility.

Local-only mode must deny external model calls and cloud fallback. Model output remains advisory. The engine checks scope and dispatches accepted actions.

Calibrate planning and evidence review separately. Use seeded cases, normal controls, and a manual comparison. Measure false positives, missed cases, latency, and reviewer effort.

Acceptance: the chosen model meets documented thresholds for its role. Injected target content cannot change scope or obtain secrets. Local-only tests produce no external model traffic.

Start with one inference service. Move to a separate GPU host only after measured contention or required isolation justifies it. A cluster needs a separate capacity decision.

## Phase 6: external cyber model

The operator identified Grok 3.7 Cyber as the intended specialist endpoint. Confirm its API URL, exact model ID, account access, and provider contract.

Record retention terms and allowed data. Keep provider keys on the host service account. Runner tools receive no keys.

External campaigns name the provider and allowed data before approval. Apply a payload allowlist and redact secrets. Redaction alone cannot authorize corporate data release.

Enforce per-call timeouts and aggregate usage limits. Record actual usage and handle provider failures without changing model policy or replaying uncertain requests.

Acceptance: tests deny unapproved providers, raw credentials, disallowed data, and exceeded budgets. Compare accepted local and external models on the same approved synthetic cases.

Unresolved provider details block this phase. They do not block the read-only dashboard or deterministic tool integration.

## Phase 7: corporate WAF pilot

Obtain the exact approved hostname and initial routes. Record methods, inputs, account roles, test window, request limits, stop contact, and access requirements.

Confirm VPN, proxy, authentication, and WAF/application log access. Treat unavailable log correlation as an evidence gap. Use a small approved route set first.

Run a normal-use baseline. Stop on suspected blocking or abnormal application effects and preserve evidence. Resolve the cause with the owner before active follow-up.

Run accepted test cases within the same campaign budget. Correlate WAF decisions with application behavior. A status code alone cannot establish a finding.

Review findings and coverage gaps before adding routes. Authenticated workflows, POST/JSON, and browser tests require their own accepted adapters.

Acceptance: the report links approved scope, actual requests, tool outcomes, WAF decisions, application effects, and reviewer conclusions. The owner confirms relevant log observations.

## Proposed repository artifacts

Paths below are planned, not implemented components.

| Path | Purpose |
|---|---|
| `lab/control/` | Shared service, state transitions, API, and storage |
| `lab/dashboard/` | Private dashboard assets |
| `lab/cli/` | Thin service client |
| `lab/schemas/` | Campaign, approval, evidence, and model contracts |
| `lab/adapters/` | Versioned tool and model adapters |
| `lab/control/migrations/` | Run index schema migrations |
| `lab/tests/control/` | State, approval, budget, stop, and recovery checks |
| `lab/tests/isolation/` | VM and network acceptance checks |
| `deployment/` | Host service and runner configuration |
| `docs/OPERATOR_RUNBOOK.md` | Setup, operation, review, backup, and recovery |

Store runtime databases, credentials, and campaign data outside tracked source. Keep synthetic test fixtures in Git. Do not commit real target evidence or keys.

## Decisions and required inputs

| Input | Needed before | Work that can continue without it |
|---|---|---|
| Dedicated host OS, hypervisor, and resources | Phase 3 | Contracts and local dashboard prototype |
| Named account authentication mechanism | Authenticated Phase 1 deployment | Synthetic read-only development |
| External hostname, route set, access, and approval | Phase 7 | All offline work |
| Local model and hardware capacity | Phase 5 calibration | Engine and deterministic adapters |
| Grok API contract and approved data policy | Phase 6 | Local inference and deterministic assessment |
| Log access and owner contact | Correlated Phase 7 conclusions | Report templates and synthetic correlation tests |
| Retention duration and backup destination | Operational evidence storage | Storage contracts and recovery fixtures |

The plan uses milestones rather than invented calendar dates. Estimate effort after Phase 0 confirms contracts and the deployment platform.

## Definition of done

The first runnable version completes Phases 0 through 3 with the existing collector on synthetic targets. It includes the read-only view, shared execution, isolation, stop controls, and recoverable evidence.

The operational lab also requires accepted local-model calibration and applicable tool adapters. External model access is an additional accepted capability.

The corporate WAF assessment completes only after an approved live campaign and human review. Reports must distinguish findings, negative results, failed steps, blocked tools, and untested objectives.

The next implementation task is Phase 0. This planning task does not authorize purchases, credential changes, provider calls, or external test traffic.
