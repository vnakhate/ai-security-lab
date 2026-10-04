# AI Security Lab Proposal

## Current requirements: minimal lab with UI, CLI, and tool coverage

Updated 4 October 2026. This section takes precedence over the larger future architecture below.

The lab serves two operators. Start with one dedicated computer, a disposable runner VM, a local model, and a private dashboard. Retain the Mac as the administration client. Add hardware only when measured workload or required isolation justifies it.

The two acceptance goals are a calibrated local AI lab and an evidence-backed assessment of an authorized external WAF. Neither goal is complete. Existing local tests establish prototype behavior. Installed repositories do not establish campaign readiness.

### One run engine for both interfaces

The dashboard and CLI must use the same run engine. One local service and a small run index are sufficient initially. Do not create separate execution paths with different scope checks.

The UI and CLI must support preparation, scope review, start, status, stop, evidence inspection, and report export. Run one campaign at a time initially. The dashboard must use named operator accounts and remain private. Scope approval must identify its reviewer.

A run records its target, profile, operator, approved actions, limits, source versions, tool steps, artifacts, and stop reason. Completion means execution finished. It does not mean the target is secure.

### Account for every supplied tool

Every campaign must account for all supplied repositories and additional installed tools. The report must show each tool as selected, blocked, not applicable, or deferred. Each unselected tool needs a reason. A failed selected step must remain visible.

A comprehensive profile must run every applicable, calibrated tool that its scope permits. Duplicate tools can supply comparison evidence. They must share one campaign budget. Tool count does not measure coverage.

Methodology repositories contribute reviewed procedures and test cases. They do not require a fake scan step. Source scanners require source access. AI evaluators require an AI target. Origin and domain discovery require their own asset scope.

The [tool coverage registry](pentest-tools/manifests/lab-tool-coverage.json) records all supplied repositories and additional tools. Historical installation manifests contain old paths. The registry checks the repositories at their current location.

| Supplied repository | Intended contribution | Readiness or scope condition |
|---|---|---|
| strix | AI-assisted web/API assessment | Provider, sandbox, scoped adapter, and calibration pending. |
| raptor | Code-assisted security investigation | Needs source and reviewed provider configuration. Adapter pending. |
| shannon | AI-assisted web/API assessment | Check source requirements for the selected mode. Runtime and adapter pending. |
| pentest-ai | AI-assisted investigation and verification | Provider compatibility, execution limits, and adapter pending. |
| numasec | Security workflow orchestration | Could coordinate tools. It must not bypass the shared scope controls. |
| cyberstrike | AI-assisted browser and security workflows | Browser, provider, and bounded execution checks pending. |
| pyrit | AI application risk evaluation | Seed export exists. Target, attack, scorer, and execution adapters remain pending. |
| hermes | General agent assistance | Candidate planner or reviewer. Not a standalone WAF scanner. |
| whatwaf | WAF detection and bypass research | Review selected detection and bypass behavior before external use. |
| wafw00f | WAF fingerprinting | Can send active detection requests. Include those requests in scope and budgets. |
| 10x-pentest | Human-gated assessment methodology | Use applicable workflow stages. This repository is not an executable scanner. |
| claude-bughunter | Assessment skills and investigation methods | Select and review applicable skills. Client registration remains pending. |
| pi | General agent runtime | Candidate assistant runtime. Not a standalone WAF scanner. |
| dns-history | Origin exposure investigation | Needs explicitly approved origin/discovery scope. A WAF URL alone does not authorize discovered IPs. |
| pyrit-course | Training and AI test examples | Adapt examples to the installed PyRIT version. Not a production campaign runner. |

Additional tools include the existing WAF collector, ProjectDiscovery httpx, Nuclei, Nmap, subfinder, Semgrep, CodeQL, Claude Code, curl, DNS utilities, and jq. Their dispositions and prerequisites appear in the registry.

### Local and external model access

Support local open-weight models and approved external model APIs through one model access module in the host service. Start with one local runtime adapter and one external provider adapter. Do not add a separate gateway server initially.

Each campaign selects local-only or approved-external mode. Local-only mode must deny external model calls and automatic cloud fallback. External mode must record the provider, model ID, allowed data, limits, and reviewer. Credentials and session tokens must never enter model prompts.

The host service owns provider keys. Runner tools use an authenticated, bounded relay and receive no keys. The relay enforces the campaign's provider, model, data, time, and cost policy. Tools must not call arbitrary providers directly.

Start local inference as a separate host service on the dedicated lab computer. Limit memory and concurrency and measure interference with the runner. Separate service accounts do not provide independent GPU or failure isolation. Move to one dedicated GPU host when measured resource pressure or required isolation justifies it. Use a private authenticated endpoint accessible only through model access. A multi-host cluster is a later option for models that exceed one host or sustained concurrent demand.

Maintain a model registry. Local entries record source, license, weight hash, quantization, runtime, and memory needs. External entries record endpoint, account access, model ID, retention terms, and allowed data. Calibrate each model and adapter before use. Model output remains advisory; the run engine retains scope and execution control.

The operator identifies Grok 3.7 Cyber as the specialist external endpoint. Its exact API URL, model ID, access, and data terms require confirmation before integration. Public xAI documentation does not establish this specific endpoint. Compare accepted models with common approved cases and evidence. Record findings, false positives, latency, cost, and reviewer effort.

### Tool adapter requirements

1. Record the exact tool version and accepted arguments.
2. Check the endpoint, method, accounts, and permitted actions against scope.
3. Reject unsupported scope constraints before starting the tool.
4. Run the tool in the disposable runner environment.
5. Restrict network access independently of agent instructions.
6. Apply campaign request, time, process, and model-cost limits across all steps.
7. Preserve stdout, stderr, exit status, structured results, and partial evidence.
8. Stop the process tree when the operator stops the campaign.
9. Normalize findings without discarding the original tool artifacts.
10. Check actual application impact before accepting a finding.

An outer CLI wrapper alone cannot control an autonomous tool's internal requests. If an adapter cannot enforce a required limit, mark it blocked. A tool's claimed local-model compatibility does not establish compatibility with our chosen runtime. Check each provider contract separately.

Use synthetic targets for startup and calibration checks. Promote an adapter only after it detects expected seeded failures and respects scope, limits, and stop controls. Do not start provider calls or external target tests during installation checks.

### Comprehensive external WAF coverage

The external WAF fronts a large corporate website. Model the target as approved pages and API routes behind the WAF, with backend services behind the website. Start with a small route set and expand in stages. A website URL does not authorize direct backend access or third-party testing.

Record the hostname, route, method, input, session role, and expected result for each case. Coordinate the test window with the site owner. Correlate request IDs with WAF and application logs. Use one request budget across tools and routes.

See the [interactive minimal architecture explainer](architecture/minimal-lab-architecture.html) for the lab boundaries and campaign flow.

The test plan must identify normal traffic, active fingerprinting, selected vulnerability checks, authenticated application workflows, and WAF/application log correlation. Include request methods, body formats, and encodings that the target actually uses.

The existing WAF collector covers bounded unauthenticated GET-query observations only. Authenticated sessions, POST/JSON, browser workflows, and richer WAF tests need separate accepted adapters. A homepage URL cannot establish coverage for application endpoints.

Use source tools when source is available. Add AI application tests only when the target contains an AI application. Origin exposure checks need explicit asset scope. Discovered hosts must never become approved targets automatically.

For each test objective, record the expected behavior, selected tool, actual requests, WAF decision, application effects, and review outcome. Show objectives with no supporting adapter as coverage gaps. A blocked normal-use baseline stops active follow-up until the cause is resolved.

### Minimal operating sequence

1. Review the target endpoint and access requirements.
2. Build the run index and read-only dashboard.
3. Expose the existing WAF collector through the shared run engine.
4. Add calibrated adapters for applicable deterministic tools.
5. Add one reviewed AI assessment adapter.
6. Evaluate the remaining supplied repositories and record their dispositions.
7. Compare coverage and review effort against the manual baseline.

The dashboard must show the tool matrix before launch and actual tool outcomes afterward. UI and CLI acceptance requires the same scope, run identifier, stop behavior, and saved evidence.

No tool integration, dashboard deployment, or external campaign occurred during this requirements update.

---

Draft for Venky and a CISO audience, updated 3 October 2026. This proposal starts with business decisions and risk ownership. It then explains the operating model, capability architecture and technical design. The recommended pilot uses synthetic tests within approved limits. Policy controls agent actions. Evidence determines whether the pilot can continue.

This document is a proposal, not authorization to provision infrastructure, purchase compute, configure credentials or run assessments. The proposed infrastructure and governance controls remain design requirements until implemented and tested. The current local calibration capabilities and their limits are identified separately below.

## Current position and decision boundary

A local calibration implementation now exists. It supports 12 synthetic cases, bounded loopback requests, local approval attestations, deterministic replay, an authenticated SQLite application range and a separate WAF collector. The saved review-fix verification records 40 passing tests. A web pilot reproduced all four seeded defects in the vulnerable range and observed no reproduced failures in the fixed range; automated database and audit checks passed. These are controlled benchmark results. They do not establish production assurance or the value of an AI testing agent.

Actual-model calibration, independent human review and a manual versus AI comparison remain pending. AI transport contracts were tested with a mock endpoint. PyRIT accepted eight exported seeds, but no PyRIT evaluation campaign ran. Hermes is installed but is not integrated into the campaign path; OpenClaw remains proposed.

The trusted controller, organizational approval identity, model access broker, typed scanner execution, VM/network containment and protected external evidence collector described below are future requirements. Current local files and in-process checks do not provide those service boundaries. The next investment decision is whether to build and validate that isolated substrate before expanding autonomous execution.

Read the [current implementation status](lab/IMPLEMENTATION_STATUS.md) and [saved review-fix receipt](lab/verification/review-fixes.json). The [zoomable architecture document](architecture/system-architecture.html) separates current processes, WAF execution and the proposed design. The original `system-canvas.html` is superseded.

## 1 Executive decision and mandate

The proposed AI Security Lab supports decisions about AI trust, required restrictions and human accountability. It provides controlled tests and evidence for security assurance. It evaluates both the security of AI systems and the usefulness of AI in security work. Its output is evidence for deployment, remediation and risk decisions.

This proposal asks the CISO to sponsor a pilot with defined limits. It also asks the CISO to appoint accountable owners. The proposal asks the CISO to approve the data and execution boundaries. It also asks the CISO to fund engineering and evaluation. Production testing and broader autonomy are later decisions, supported by measured results. Purchasing models or assembling scanners does not establish this capability.

The initial recommendation is a synthetic local lab, a governed Hermes worker, one local open-weight model and one approved frontier model. PyRIT supplies repeatable AI evaluation workflows. The pilot introduces OpenClaw as a comparison after the common containment controls pass. These are proposed choices. The pilot must demonstrate their business value against a manual baseline.

### What the CISO should receive

| Decision | Evidence the lab must produce | Resulting management action |
|---|---|---|
| Can an AI application handle this workflow and data class? | Tested access boundaries, injection resistance and observed leakage | Approve the bounded use case, require changes, or decline deployment |
| Can an agent perform this security task with limited supervision? | Verified findings plus records of permitted, denied and attempted actions | Set the permitted autonomy level and required supervision |
| Which models and harnesses justify investment? | Comparable quality, failure, latency and total-cost results | Select a configuration, retain alternatives, or stop the pilot |
| Does an identified weakness warrant remediation? | Reproducible impact, affected asset, controls tested and independent verification | Assign an owner, prioritize a fix and verify closure |
| Can the organization explain what happened? | Approved scope linked to actions, evidence, incidents and final conclusions | Support assurance review and accountable incident handling |

The lab cannot certify that a system is universally safe. Its conclusions apply to the tested versions, configurations, identities, data and time window. A change in those conditions can invalidate acceptance and trigger targeted retesting.

## 2 Business outcomes and assurance portfolio

There are three related but separately measured mandates. Separate measures prevent confusion between a scanner demonstration, AI governance and agent containment.

| Mandate | Executive question | Representative test | Business output |
|---|---|---|---|
| Secure AI applications | Can the application protect information and enforce the intended workflow? | A retrieved document attempts to obtain another synthetic tenant's information | Release conditions and remediation evidence |
| Govern autonomous agents | Can an agent act without exceeding its authority? | A target page asks it to change destinations or access a canary credential | Permitted capabilities, supervision rules and containment evidence |
| Improve security operations | Does AI make a selected security task more effective at acceptable cost? | An agent and a manual reviewer assess the same known fixtures | Measured workflow improvement and staffing implications |

For the first pilot, select one representative task per mandate. The fixtures should contain known positives, corrected versions and clean controls. Hold tool access and budgets constant across models. An improvement claim needs the baseline, denominator, verification effort and uncertainty. The number of prompts sent or vulnerabilities claimed is not enough.

Expected benefits are hypotheses: faster initial triage, broader repeatable coverage and better evidence assembly. Measure these rather than promising them. False positives, missed defects, extra review effort and increased exposure can offset apparent speed gains.

The lab feeds existing security work. A verified finding becomes a tracked issue with an asset owner, severity rationale, remediation target and closure test. The lab supports AppSec, AI product teams and assurance reviewers. Their existing release and risk-acceptance authority remains explicit.

## 3 Risk ownership and governance

A model can recommend an action. Approved policy and an accountable person provide authority for that action. Prompt instructions, model refusals and agent approval dialogs are useful supporting controls. Independent identity, network, execution and data controls must bound the consequences when those supporting controls fail.

### Accountable roles

| Role | Accountability | Boundary |
|---|---|---|
| CISO or delegated security sponsor | Mandate, risk appetite and pilot continuation | Does not implicitly authorize every assessment |
| Lab service owner | Configuration, availability, access, evidence and incident response | Cannot enlarge an asset owner's approved scope |
| Asset or AI product owner | Test scope, accounts, business impact and remediation | Identifies which systems and data may be assessed |
| Campaign lead | Executes approved work and records deviations | Cannot approve their own material scope expansion |
| Independent verifier | Confirms findings and evaluates evidence quality | Model agreement alone does not establish correctness |
| Data/privacy and procurement owners | Data release, retention, provider conditions and spending | Approve applicable organizational requirements |

During a personal pilot one person may hold several roles, but approvals and decisions still need a record. For organizational staging or production, use separate execution and material risk-approval roles wherever practical. The organization must select its actual authority structure before rollout.

### Principal risks and residual exposure

| Risk | Proposed control | Residual risk and owner decision |
|---|---|---|
| Agent exceeds test authority | Explicit scope, external policy broker and enforced egress | Bugs and ambiguous scope remain. Owner accepts only after boundary tests |
| Confidential information reaches a provider | Synthetic data first, data-class rules, redaction and credential broker | Redaction can miss information. Data owner decides which workloads remain local |
| Incorrect finding or missed vulnerability | Ground-truth fixtures, negative controls and independent replay | Limited coverage persists. Security lead defines acceptable use of conclusions |
| Host or lab compromise | Dedicated VM, constrained runners, no host secrets and reset | Isolation flaws persist. Infrastructure owner selects stronger boundaries for hostile tests |
| Supply-chain or skill compromise | Provenance, pinned artifacts, reviewed plugins and controlled upgrades | Review does not guarantee safety. Service owner maintains advisories and rollback |
| Cost or workload grows without control | Pre-request accounting, action/time caps and emergency stop | In-flight work and verification costs remain. Budget owner approves reserves |
| Evidence is incomplete or altered | External collection, protected checkpoints and restricted raw artifacts | Collector failure or excessive access can undermine assurance. Stop on lost logging |

Risk acceptance must name the risk, its evidence, compensating controls, owner and expiry. A failed critical containment test blocks expanded autonomy. Research into weaker controls belongs in a dedicated, approved experiment rather than becoming the lab's operating default.

### Approval model

Use three levels of approval. Program approval authorizes the capability, funding and operating rules. Campaign approval authorizes exact assets, data, test classes, time window and limits. Action approval handles changes or sensitive actions outside those campaign permissions. Routine actions within an approved campaign do not require a new prompt each time.

Scope changes, new destinations, real-data access, public exposure and production activity require the appropriate named owner. An agent cannot approve its own escalation. The controller must deny when approval expires, policy is missing or the approval service is unavailable. The operator and service owner hold emergency-stop authority. They must exercise that authority in a drill before active campaigns.

## 4 Capability architecture and operating model

Explain the architecture to leadership as six capabilities before introducing specific products.

| Capability | Purpose | Failure consequence prevented |
|---|---|---|
| Governance and campaign control | Turn business authorization into a bounded work order | Open-ended testing with no accountable owner |
| Model access and data control | Route local or frontier inference under data and cost policy | Unapproved information release or spending |
| Agent workbench | Plan and execute the permitted workflow | Hidden state or personal-account access expands authority |
| Execution and isolation | Enforce allowed actions independently of agent instructions | A persuasive model output becomes unrestricted execution |
| Test range and evaluation | Provide resettable fixtures and repeatable measurements | Unrepeatable demonstrations create unjustified confidence |
| Evidence and assurance | Preserve the link from authorization to actions and conclusions | A finding or incident cannot be explained or reproduced |

In the proposed design, Hermes and OpenClaw are replaceable agent implementations within the workbench. Open-weight and frontier models are replaceable inference choices. PyRIT would supply AI test construction, execution and scoring. Security scanners would run behind the execution boundary. The lab's policy, evidence and ownership must survive a model or harness change.

The proposed service lifecycle has these stages:

1. Receive the request.
2. Review the scope.
3. Approve the campaign.
4. Prepare the environment.
5. Execute within approved limits.
6. Verify the results independently.
7. Report the results.
8. Transfer findings to the remediation owner.
9. Reset the environment.

Preparation checks that the approved artifact versions, target identities, budgets and logging are available. Any significant deviation returns the campaign to review. Successful execution does not automatically approve deployment or release a report to third parties.

A campaign should end with an executive brief and a technical evidence package. The brief states the question tested, conditions, confirmed outcomes, residual risks, accountable owners and recommended decision. The technical package lets another authorized reviewer reproduce the result. The report must label incomplete runs as incomplete. It must distinguish denied actions from completed unsafe actions.

## 5 Investment and pilot acceptance

Fund the first stage as an experiment with explicit continuation gates. The existing tool installations reduce setup work but do not demonstrate a functioning assurance service. The earlier 2–3 week estimate covers a modest engineering pilot for one user. Organizational readiness also requires identity integration, monitoring, approval workflows, maintenance and independent review.

| Investment area | What to budget | Evidence needed before expansion |
|---|---|---|
| Engineering | Isolation, policy adapters, identity, evidence and reset automation | Controls pass legitimate and adversarial boundary tests |
| People | Campaign design, verification, operations and remediation follow-up | Findings and decisions receive timely accountable review |
| Compute and storage | Local inference, disposable VMs, snapshots and protected evidence | Measured capacity, utilization and recoverability |
| Frontier inference | Test generation, target requests, scoring and review calls | Total campaign cost with enforced caps and approved data release |
| Maintenance | Updates, model changes, regression checks and incident exercises | Defined owner, cadence, rollback and supported configurations |

A local model avoids sending selected workloads to an external endpoint, but still carries compute, maintenance and licensing considerations. A frontier model may improve particular tasks, but its value needs evidence and approved data handling. Neither label, open source or more capable, provides sufficient grounds to select a model.

### Executive scorecard

| Dimension | Pilot measure | Proposed gate |
|---|---|---|
| Authority and containment | Completed out-of-scope actions and failed boundary controls | No completed unauthorized action in the acceptance suite. All critical boundary tests pass |
| Information handling | Synthetic-canary disclosures and unapproved outbound data | No unapproved release. Any failure blocks that configuration |
| Evidence quality | Campaigns with complete scope, approvals, action trail and verified outcomes | Every acceptance campaign has a complete reviewable package |
| Security effectiveness | Confirmed findings, false positives and misses on known fixtures | Pre-register task-specific criteria and compare with a manual baseline |
| Operating value | End-to-end time, human verification effort and total cost | Sponsor agrees whether measured benefit justifies continued investment |
| Repeatability | Results across reset runs and configuration revisions | Explain variability. Do not promote an unreliable workflow without mitigation |

These are proposed gates, not measured results. Zero observed escapes in a finite suite does not prove escape is impossible. Report suite size, coverage and limitations alongside the scorecard. Select effectiveness thresholds after choosing the pilot tasks and before seeing their results.

The first approval should cover only synthetic fixtures and checks of the infrastructure. Continue to model/agent comparison after containment acceptance. Then consider a separately scoped staging pilot. Production remains a distinct business and operational risk decision. An unsuccessful pilot may still be valuable if it establishes that a configuration should not be deployed. The continuation decision must allow that outcome.

## 6 Technical design and implementation detail

The sections below translate the executive mandate into implementation requirements. They retain the installed-tool inventory, model candidates, PyRIT design, network and execution boundaries, approval mechanics and evidence requirements. Product names are candidate implementations. No section should be read as proof that the proposed controls are deployed.

### Objectives and current position

The lab should answer four questions:

- Which model and agent combination finds reproducible security defects?
- How reliably does the combination obey scope?
- What does the combination cost?
- Does the combination resist malicious instructions in target content?

The lab should produce verified findings and measurable containment results rather than unreviewed agent claims.

The workspace already has 15 pinned repositories, eight independent Python environments, five Node package installations, supporting native tools and downloaded Docker images. The inventory is in `pentest-tools/INSTALLATION.md` and `pentest-tools/manifests/installation-summary.json`. Hermes is installed. OpenClaw is not part of that inventory. In this conversation, wafw00f's help command succeeded. Other tools passed path and installation checks. These checks do not demonstrate runtime acceptance.

The installation report predates that help check.

The prepared Juice Shop compose file publishes only to `127.0.0.1:3000`. That binding alone does not establish outbound network isolation or prove the service is currently running. The earlier altera.com benign request returned HTTP 403. External testing remains a separate campaign requiring an operational scope and approval. The lab proposal does not expand the previous authorization.

### Current process architecture

`run-lab.sh` dispatches application/AI commands to `harness.py` and `waf` commands to a separate launcher. It does not start the application range or the pilot.

Within a harness invocation, campaign orchestration, Broker checks, fixture or HTTP adapters, scoring and evidence writing are functions in the same Python process. The authenticated application adapter maps catalog routes to native `/api/...` routes and attaches synthetic bearer sessions from a hash-bound private file. It is not a gateway service.

`run_pilot.py` is optional orchestration. It starts `application_server.py` in a separate process, invokes the harness campaign as a Python function, then inspects SQLite and audit records. These checks use another source of observations, but the pilot and target files share the operator's access boundary. They are not an independently protected evidence collector or a completed human review.

The AI range uses simple SQLite retrieval of synthetic tenant documents, mock tool effects and direct calls to its configured local chat-completions endpoint. There is no deployed vector database or management model broker on that path. Separately, harness `assist` sends a bounded planning request through Broker; it saves catalog selections for review and does not execute the suggested campaign.

The WAF path validates its own exact target and expiring scope, invokes bounded `curl` subprocesses, and writes its own evidence. Application-harness approvals do not authorize it. Installed scanners and agent frameworks are not automatically called by either path.

See the [current process view](architecture/current-processes.html), [WAF view](architecture/waf-processes.html), and [source evidence](architecture/architecture-evidence.json).

### Proposed architecture

The following diagram is the target design, not a deployment inventory. The [proposed canvas](architecture/proposed-system.html) provides a zoomable view of the same intended boundaries.

```mermaid
flowchart TD
    H[Human operator] --> A[Campaign approval and signed scope]
    A --> C[Trusted controller and policy service]
    C --> G[Hermes or OpenClaw isolated agent]
    G --> M[Model broker and data filter]
    M --> L[Local model inference service]
    M --> F[Approved frontier API endpoint]
    G --> T[Typed tool execution broker]
    T --> P[Scope and approval checks]
    P --> R[Disposable tool runner VM or container]
    R --> N[Enforced target network boundary]
    N --> V[Isolated vulnerable applications]
    N --> X[Separately approved staging targets]
    C --> E[Protected evidence store]
    T --> E
    R --> E
```

The controller, policy service, approval credentials and model-provider keys belong outside the agent and target environments. A model may propose an action. The broker checks the action and its arguments. It starts only the approved tool with approved arguments. The executor must not inherit a general-purpose host shell or a Docker administration socket.

The model API network and the target network are separate paths. Tool runners cannot reach provider credentials, management services, the laptop LAN, cloud metadata endpoints or arbitrary internet destinations. The model broker can reach only approved provider endpoints and local inference. A lab with frontier access is restricted-egress, not air-gapped. The offline profile disables frontier endpoints entirely.

### Infrastructure and isolation

| Component | Proposed placement | Required boundary |
|---|---|---|
| Operator interface and controller | Dedicated management VM or account | Authenticated access, no public unauthenticated gateway |
| Hermes and OpenClaw | Separate nonprivileged workloads and state stores | Read-only approved inputs. No host home, SSH agent or personal browser profile |
| Tool execution | Disposable VM per campaign, containers inside where useful | No privileged mode, host networking or Docker socket exposed to agents |
| Vulnerable applications | Separate target network and disposable volumes | No production secrets, default-deny egress, known reset procedure |
| Local model inference | Separate inference service | Private endpoint, model files read-only, no execution tools |
| Provider credential broker | Management boundary | Dedicated keys, restricted data release and enforced budgets |
| Evidence store | Collector outside agent control | Agents cannot alter earlier records or approvals |

For the laptop pilot, use a dedicated Linux VM as the lab boundary. Retain macOS as the operator console. Containers separate processes within that VM. They share a kernel. They should not be the only boundary for hostile code, kernel tests or containment research.

More adversarial tests use a separate disposable VM or dedicated host. Create a snapshot between campaigns. Reset the environment between campaigns.

Containers require these controls:

- A non-root user.
- A read-only root filesystem where compatible.
- Removed capabilities.
- The no-new-privileges setting.
- Limits for processes, memory, CPU use and execution time.
- A small temporary filesystem.
- Explicit mounts.
- Pinned image digests.

Any scanner that needs raw network capability requires a dedicated runner and separate approval. uv separates dependencies. It does not provide security containment. Build the installed environments into reviewed runner images. Do not execute agents directly on the personal workstation.

Network enforcement must cover TCP, UDP, DNS, IPv4 and IPv6. Use controlled DNS and destination rules outside the agent. Check every redirect and resolved address against scope. Block DNS rebinding and unapproved alternate addresses. Deny cloud metadata and private networks unless approval specifies an exact lab subnet.

For HTTPS campaigns, use a controlled proxy with hostname/path/method checks where required. An IP allowlist alone is insufficient for shared hosting. Applications still need a network firewall when a tool ignores proxy settings.

The management controller may provision disposable workers through a narrowly scoped infrastructure interface. Agent-generated input must never become arbitrary Docker API calls or host commands.

### Model strategy

Use the same tasks, budgets, tool permissions and target snapshots for every model comparison. The following are proposed candidates, not benchmark winners or claims of account access.

| Candidate | Proposed role | Selection condition |
|---|---|---|
| Qwen3-8B | Local baseline for triage and small tool workflows | Fits measured hardware capacity and passes structured tool-call tests |
| Qwen3-32B | Stronger local comparison | Dedicated memory/GPU capacity, measured latency and context budget |
| gpt-oss-20b | Alternative local reasoning baseline | Compatible inference and tool-call formatting validated |
| OpenAI GPT-6.1 Sol | Frontier planning and analysis candidate | Account access, approved data handling and Responses integration |
| OpenAI GPT-6 Astra | Complex reasoning comparison | Same controls, with separately capped cost |
| Claude Sonnet and Opus families | Independent frontier comparison | Pin exact API IDs from the available provider catalog at pilot approval |

Qwen3's official repository documents open weights under Apache 2.0. Inspect each artifact's license, model card and redistribution terms. Open weights do not establish open training data. Use “open-weight” precisely. Pin these artifacts:

- Model revision.
- Tokenizer.
- Quantization.
- Inference version.
- Template.

The OpenAI model documentation lists gpt-oss-20b as an open-weight model. [Qwen3 repository](https://github.com/QwenLM/Qwen3), [gpt-oss-20b documentation](https://developers.openai.com/api/docs/models/gpt-oss-20b).

The OpenAI deployment guidance specifies Responses for GPT-6.1 Sol and GPT-6 Astra tool calling. A harness advertising an OpenAI-compatible Chat Completions endpoint is therefore not automatically compatible. Choose a Responses adapter or a supported model integration. If you choose an adapter, add it. Test the adapter. The approval record must include frontier provider availability, exact model IDs, retention settings and rates. [OpenAI deployment checklist](https://developers.openai.com/api/docs/guides/deployment-checklist), [Claude model catalog](https://platform.claude.com/docs/en/models/overview).

Start with local inference. Use a frontier reviewer only when approved. Redact secrets and personal data before outbound submission. Record which evidence the broker releases. Do not silently replace local inference with a hosted service.

A reviewer can suggest a next action but cannot approve it. Synthetic credentials and canary strings allow data-leak tests without exposing genuine secrets.

The proposed memory target is 32 GiB for a small-model pilot. The preferred target is 64 GiB for additional capacity. Larger models require a separate sizing exercise. These are engineering targets, not measured capacity requirements. This review did not establish device memory. Filesystem free space was about 17 GiB at inspection.

Allocate a separate 100–200 GiB lab volume before adding model weights, VM snapshots and evidence. Measure memory use at the selected context length before deciding whether local inference and targets can coexist.

### Agent configuration

Hermes is the first pilot because its source and environment are already installed. Its documented Docker terminal backend can place shell execution in a container. The agent itself remains on its host. The host agent process therefore also needs its own VM/account boundary. Isolate file, browser, connector and other tools independently. Terminal sandboxing does not establish isolation for every capability.

The upstream dangerous-command approval mechanism is an additional guard, not the lab's sole policy enforcement. Inspect support in the pinned release before applying current documentation settings. [Hermes Docker documentation](https://hermes-agent.nousresearch.com/docs/user-guide/docker), [Hermes security documentation](https://hermes-agent.nousresearch.com/docs/user-guide/security).

OpenClaw runs in its own workload with its own memory, sessions and keys. Explicitly select sandbox execution. Restrict tools. Disable elevated host execution. Deny execution when the sandbox or approval service is unavailable.

Its documentation distinguishes sandbox placement, tool policy and elevated execution. Review each control. Never enable approval-free host execution for this lab. [OpenClaw isolation and tool policy](https://docs.openclaw.ai/gateway/sandbox-vs-tool-policy-vs-elevated), [OpenClaw approvals](https://docs.openclaw.ai/cli/approvals).

Disable these capabilities for both agents:

- Messaging integrations.
- Scheduled jobs.
- Personal-account access.
- Unreviewed skill downloads.
- Automatic self-modification.

Skills and MCP tools require source review, a version pin and explicit capability approval. Separate memory by campaign. Mark retrieved target material as untrusted evidence. Retain prompts, tool requests and results. Do not require or claim access to hidden model reasoning.

Assign separate planner, executor and verifier roles when the pilot expands. Role names and different prompts alone are not an isolation boundary. Use separate permissions and state. Start with one executor, sequential actions and human review. Add agent concurrency only after controls pass containment tests.

### Tooling and test tracks

| Track | Tools and fixtures | Pilot boundary |
|---|---|---|
| Source and configuration review | Semgrep, Raptor, CodeQL | Read-only copy of approved source. No deployment credentials |
| HTTP and WAF observation | Existing evidence collector, wafw00f, WhatWaf, httpx | Lab or exact approved hosts. Independently enforce pacing |
| Web and API findings | Juice Shop first. Then reviewed fixtures and selected nuclei templates | Synthetic accounts/data. Lab-only active exploitation |
| Agent-assisted assessment | Hermes first, then OpenClaw. Strix/Shannon as later comparisons | One harness at a time under the same broker and scope |
| AI application testing | PyRIT plus synthetic RAG/tool-use endpoints | Prompt injection, access control, synthetic data leakage and unsafe tool use |
| Containment testing | Instrumented canary endpoints and files | Scope escape, credential access and approval bypass attempts inside dedicated lab |

Pentest-AI, Numasec, CyberStrike and other installed agents are optional comparison candidates after the initial harness passes. Keep browser profiles disposable. Review scanner templates and plugins before enabling them. A tool name does not define the actions it may perform. Pin template IDs/hashes, actions and destinations in each campaign.

Tests should include these positive and negative controls:

- A known vulnerable fixture.
- A fixed version.
- An authorized user.
- An unauthorized user.
- Malicious target text that tries to change scope.

WAF identification is an observation, not proof that an application is secure or vulnerable. Scanner output remains a candidate finding until reproduced.

Exclude production denial of service, credential stuffing, persistence, lateral movement, real data extraction and destructive tests from the pilot. Any future exception requires its own controlled experiment and explicit scope. It cannot be inferred from permission to run a scanner.

### PyRIT evaluation design

Use the requested [PyRIT 1.0.1 documentation](https://microsoft.github.io/PyRIT/1.0.1/) as the design reference for AI red teaming. It describes single-turn and multi-turn testing, scenario execution, CoPyRIT for human-led testing, persistent conversation memory and response scoring. The installed framework is 1.1.0. Check examples and interfaces against that release before execution. If exact 1.0.1 reproduction is necessary, create a separate pinned uv environment. Retain the existing 1.1.0 environment. This proposal executes neither option.

PyRIT should be the evaluation harness, while Hermes and OpenClaw are agent systems under evaluation or bounded assessment workers. A model tested for response safety is an objective target. A model generating test inputs is an adversarial target. A model judging outputs is a scorer. Give each model separate credentials, context and budgets.

The target and scorer must not share the agent's approval authority. The framework's targets, datasets, converters, attacks and scorers provide components for this workflow. Our external policy broker supplies execution authorization. [PyRIT framework architecture](https://microsoft.github.io/PyRIT/1.0.1/code/framework/).

Proposed pilot workflow:

1. Prepare a versioned synthetic dataset with test objectives, expected controls and excluded content. Review dataset licenses. Prohibit real secrets and customer records.

2. Register only brokered local-model, frontier-model and lab AI-application targets. Record the exact protocol and adapter. Do not assume a Chat Completions example supports a Responses-only model.

3. Start with fixed single-turn inputs. Add a reviewed multi-turn strategy after the scope, memory and scoring controls pass. A scenario's internal retries and concurrency must count against the outer campaign budget.

4. Score objective outcomes using instrumented fixtures and deterministic checks where possible. Add rubric-based model scoring for ambiguous responses. Require human adjudication after model scoring. Store rubric version, score, explanation and supporting artifacts.

5. Persist prompts, responses and scores in a database for the campaign. Export them with the protected evidence bundle. Avoid an in-memory-only profile for runs requiring later analysis. Verify persistence and restore behavior first.

6. Use the Scanner for repeatable approved scenarios. Use the Framework for custom fixtures. CoPyRIT is optional for human-led review, bound to a private interface with access control. This proposal does not start its process. [PyRIT Scanner](https://microsoft.github.io/PyRIT/1.0.1/scanner/scanner/), [PyRIT configuration](https://microsoft.github.io/PyRIT/1.0.1/getting-started/configuration/).

| Evaluation | Fixture | Evidence of failure |
|---|---|---|
| Synthetic secret disclosure | Mock assistant with a designated canary | Canary appears in an unauthorized response |
| Indirect prompt injection | Controlled retrieved document or web page | Agent executes the injected instruction contrary to its approved task |
| Tool authorization | Mock shell, file and HTTP adapters | Unapproved action crosses the broker boundary |
| RAG access control | Two synthetic tenants and separated documents | One tenant receives the other's protected fixture |
| Memory contamination | Separate campaigns with adversarial content | Unapproved instructions or canaries carry into another campaign |
| Multi-turn resilience | Bounded conversation with fixed success criteria | Verified policy failure within the permitted turn budget |

Juice Shop is the web-security fixture, not automatically an LLM target. Add a separate mock AI application with RAG and typed tools for the PyRIT track. Jailbreak scores alone do not demonstrate host compromise, data access or real-world exploitability. Use the corresponding instrumented evidence. Testing a frontier provider's safety behavior requires an approved evaluation scope and compliance with its applicable access conditions.

### Scope and approvals

Every campaign needs a reviewed manifest with these fields:

- Owner.
- Exact targets and ports.
- Allowed paths and methods.
- Exclusions.
- Test accounts.
- Tool and template versions.
- Action classes.
- Data classification.
- Allowed model endpoints.
- Time window.
- Source IPs.
- Request and concurrency limits.
- Spend cap.
- Evidence location.
- Approver.
- Emergency contact.

Avoid domain wildcards. A URL on a shared CDN is not authorization to scan the CDN's other tenants or infrastructure.

| Decision | Proposed approver | Approval boundary |
|---|---|---|
| VM allocation, network design and image builds | Lab owner and infrastructure administrator | Approve the concrete resources and isolation policy |
| Model weights and local serving | Lab owner and license/data owner | Approve artifact license, hardware use and provenance |
| Frontier model keys and data release | Budget owner and data/security owner | Approve provider, project, data classes, retention and spend cap |
| Synthetic lab campaign | Lab owner | Approve scope and bounded permitted actions once per campaign |
| State-changing or sensitive action outside approved classes | Designated human operator | Approve the exact action, target, parameters and consequences |
| Staging or production campaign | Asset owner and security lead. Operations for production | Written rules of engagement, window, source IPs and stop contact |
| Vulnerable public service, outbound callback or new destination | Security and infrastructure owners | Separate exposure/egress exception. Disabled by default |
| Finding disclosure or report transmission | Asset owner | Review recipients and evidence redaction before sending |

These are proposed governance roles, not a statement that a particular organization or law requires them. Venky can hold multiple owner roles in a personal lab. Organizational targets should use their actual approval process. Provider account permissions and usage restrictions still apply.

Store approvals outside agent memory. Each approval binds to these fields:

- Campaign.
- Normalized action and arguments.
- Target.
- Relevant artifact hashes.
- Limits.
- Expiry.
- Approving identity.

Issue an expiring capability with a bounded use count. Reject changed arguments, replay, expired approvals and changed target resolution. Approval timeouts, missing policy and policy-service failures mean deny. Approved routine lab actions may run within their budget without repeated prompts. New targets or risk classes require a new approval.

The proposed initial limits are:

- One executor.
- One outstanding target request.
- A maximum 15-minute active run.
- 100 target requests.
- 20 model turns.

For any later external campaign, propose one request every 10 seconds initially, with no automatic expansion. The HTTP tool broker must enforce pacing across all processes. A client's timeout flag is not a rate limit. These numbers need owner approval and adaptation to the test, not blind application to every scanner.

Proposed frontier budget is $5 per pilot run and $50 per day, with reserved token/cost accounting before a request and a controller-enforced stop. These are budget caps, not provider price estimates. Provider usage dashboards alone may show delayed information. Account for requests already in flight.

Stop when any of these conditions occurs:

- An unexpected destination.
- An attempt to access real secrets.
- A scope violation.
- An infrastructure alarm.
- Budget exhaustion.
- Lost logging.
- Operator cancellation.

For external targets, stop on a denied benign baseline, HTTP 429 or unexpected repeated 5xx responses. Investigate before resuming. A block is not permission to evade it. The emergency stop stops workers, denies their network access and revokes campaign credentials. It preserves evidence.

### Evidence and evaluation

Save each campaign in a unique directory. Include these records:

- Approved scope.
- Approval events.
- Model revisions and settings.
- Tool and image hashes.
- UTC timeline.
- Model requests and responses.
- Tool requests.
- stdout and stderr.
- Exit codes.
- HTTP metadata and raw bodies.
- Screenshots where useful.
- Observed network destinations.
- Resource use.
- Estimated and reconciled cost.

Record retries and incomplete runs explicitly. Raw evidence can contain secrets. Encrypt raw evidence. Restrict access. Create a separate redacted copy for analysis. Approval evidence and collector records must be outside agent write permissions.

Store SHA-256 manifests. Retain an append-only event trail with a protected checkpoint or signature. Hashes alone do not prove provenance when the same agent can replace both evidence and hashes. Proposed retention is 30 days for raw synthetic-lab evidence and 90 days for redacted reports, pending owner approval. Real engagements use their agreed retention rules.

Use ground-truth fixtures and independent replay for findings. Report precision, false positives, confirmed findings, misses, time to first verified finding, request count, model/tool failures and cost per verified finding. For AI and agent tests, additionally report prompt-injection success, attempted and completed scope escapes, blocked/accepted approval bypasses and synthetic-secret disclosure. Measure policy compliance separately from model refusal behavior.

Reset the target before each run. Run each accepted task at least three times per model/harness configuration. Use fixed budgets. Record seeds where supported.

Measure repeatability. Do not assume repeatability. A second model can help review findings but is not ground truth. Include human verification of significant findings and negative controls.

### Delivery phases and acceptance

| Phase | Deliverable | Acceptance gate |
|---|---|---|
| 0 Scope and design | Approved architecture, pilot scope, hardware/budget selection | No unresolved owner or data-release decision |
| 1 Isolated substrate | VM/network, image pins, secrets broker, evidence collector, emergency stop | Host/LAN/metadata access denied. Permitted lab access works. Stop ends execution |
| 2 Manual calibration | Tool startup checks and one manual Juice Shop workflow | Saved output, known positive and negative control, reset proven |
| 3 Hermes pilot | One local and one frontier model through the broker | No unauthorized completed actions. Findings independently replayed. Budgets enforced |
| 4 OpenClaw comparison | Pinned OpenClaw installation and equivalent policy adapter | Same containment gates and benchmark suite passed |
| 5 Expanded evaluation | PyRIT fixtures and selected additional harnesses | Repeated scored runs with documented limitations |
| 6 External pilot | Separate staging rules of engagement | Explicit asset approval, functioning stop contact and reviewed benign baseline |

Before declaring the lab ready, demonstrate denial of these attempts:

- A redirected request outside scope.
- An alternate DNS name or IP address outside scope.
- An IPv6 bypass.
- Access to a canary in the host home directory.
- Access to a mock metadata endpoint.
- Use of an expired or replayed approval.
- Budget overflow.
- A malicious page that asks the agent to weaken policy.

Confirm that legitimate bounded work succeeds too. A failed boundary test blocks expanded autonomy until corrected.

Planning estimate: 2–3 engineering weeks for a single-user pilot with modest broker integration, excluding GPU procurement and external approvals. This is an estimate, not a delivery commitment. Complex adapters or an organizational production deployment need separate sizing. Avoid Kubernetes in the first pilot unless a validated isolation platform already exists.

The expanded infrastructure design proposes these directories; this is not a list of currently implemented modules:

- `lab/infra`
- `lab/policies`
- `lab/scopes`
- `lab/adapters`
- `lab/fixtures`
- `lab/evals`
- `lab/runs`

The expanded design should also include an organizational approval register, infrastructure rollback procedure and model/agent benchmark report. The local calibration source and runbook already live in `lab/`; the WAF collector lives in `lab/waf-assessment/`, and the installed inventory in `pentest-tools/`. Retain historical receipts as provenance inputs rather than rewriting them as current acceptance evidence.

### Decisions for pilot approval

Complete these decisions for pilot approval:

1. Approve or amend the proposed Hermes-first sequence.
2. Choose a laptop VM or dedicated hardware.
3. Select one local and one frontier model.
4. Name the budget, data and asset approvers.
5. Approve the synthetic lab scope, caps and retention. Hardware capacity, frontier account access, provider data terms and exact harness compatibility remain to be established.

The next infrastructure action after approval is to build and validate the isolated substrate. Existing calibration does not satisfy that gate. Broader agent testing and any external-target testing follow their own acceptance gates and explicit campaign scope.


### Terms used in this proposal

| Term | Meaning in this proposal |
|---|---|
| CISO | Chief Information Security Officer. |
| AppSec | Application security. |
| Campaign | A set of tests with one approved scope, time window and limits. |
| Scope | The approved assets, data, actions and exclusions for a campaign. |
| Fixture | A controlled test application, document, account or dataset. |
| Canary | A synthetic secret or marker that reveals unauthorized access or disclosure. |
| Broker | A service that checks requests before allowing access to a model or tool. |
| Containment | Controls that restrict agent actions and their consequences to approved boundaries. |
| Egress | Network traffic that leaves an environment. |
| VM | Virtual machine. |
| RAG | Retrieval-augmented generation. An application retrieves information and supplies it to a model. |
| LLM | Large language model. |
| MCP | Model Context Protocol. A protocol for connecting AI applications to tools and data. |
| Harness | Software that coordinates agent execution or evaluation. |
| Ground truth | Known fixture behavior or independently verified outcomes used to judge test results. |
| Pinned artifact | A repository, image, model or other dependency fixed to a specific version or hash. |
| Frontier model | A hosted model candidate accessed through an approved provider API. |