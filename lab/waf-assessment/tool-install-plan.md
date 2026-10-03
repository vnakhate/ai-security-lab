# Pentest tool installation plan — isolated uv environments

Updated 2026-10-02. Installation completed in `../../pentest-tools/` under the instruction to install without executing pentest tools. See [installation report](../../pentest-tools/INSTALLATION.md) and [inventory](../../pentest-tools/manifests/installation-summary.json). CLI smoke checks, credentials, container startup and lab calibration were deliberately not performed. The acceptance steps below that require running tools remain deferred.

## Installation layout

Use `/Users/venky/work/preprod/waf/pentest-tools/` as the installation root. Keep the assessment collector in `lab/waf-assessment/` as the WAF assessment module of the AI security lab.

```text
pentest-tools/
  repos/              reviewed repository checkouts at pinned commits
  uv-tools/           one uv-managed environment per Python CLI package
  bin/                uv CLI executables and explicit tool wrappers
  cache/uv/           shared download cache; not a shared Python environment
  python-envs/        per-tool environments where a project lock is unavailable
  node-tools/         npm projects with package-lock.json
  manifests/          refs, versions, platform details and dependency snapshots
  logs/               installation and smoke-test results
  lab/                disposable local targets and Docker configuration
  secrets/            excluded from archives/version control; tightly restricted
```

Use Python 3.12 as the initial compatibility baseline, managed by uv rather than replacing the system/Homebrew interpreter. Verify every pinned tool's declared Python requirement before installing it. Current upstream metadata allows 3.12 for Strix, Raptor, Hermes and PyRIT. Their requirements differ; do not assume that the local Python 3.14 is suitable for every release. [Strix metadata](https://raw.githubusercontent.com/usestrix/strix/main/pyproject.toml), [Raptor metadata](https://raw.githubusercontent.com/gadievron/raptor/main/pyproject.toml), [Hermes metadata](https://raw.githubusercontent.com/NousResearch/hermes-agent/main/pyproject.toml), [PyRIT metadata](https://raw.githubusercontent.com/microsoft/PyRIT/main/pyproject.toml).

uv environments isolate Python dependencies. They do not sandbox filesystem access, network access or credentials. Execute autonomous tools only in their reviewed container/VM and approved disposable staging/lab setup.

## Verified local starting point

- Platform: macOS arm64; uv 0.12.1; Python 3.14.6; Node 25.3.0.
- Found on PATH: Docker CLI, node/npx, Python, pipx, uv, Go, subfinder, httpx, nmap, nuclei and dig.
- Not found on PATH: strix, ptai, numasec, cyberstrike, wafw00f and whatwaf.
- No matching pentest repository directories found in the common project/tool locations inspected. This is not an exhaustive disk search.
- Docker daemon state, image compatibility, Bun availability, agent authentication and external tool acceptance are not verified.
- Existing recon binaries require version/vendor verification, especially httpx, whose name can refer to a different Python package.

## Tool-to-runtime mapping

| Tool | Planned installation | Runtime boundary | Priority |
|---|---|---|---|
| Custom WAF collector | Keep current standard-library Python package | Existing launcher; no extra packages | Already available |
| wafw00f | Pinned package using uv tool install | Dedicated uv CLI environment | Wave 1 |
| Pentest-AI | Pinned ptai package using uv tool install | Dedicated uv CLI environment; optional scanner binaries separate | Wave 1 |
| Strix | Pinned source checkout; committed uv.lock and uv sync | Repo .venv plus Docker sandbox/model provider | Wave 2 |
| Raptor | Pinned source checkout; uv sync --locked | Repo .venv plus Claude Code and separate scanner runtimes | Wave 2 |
| Semgrep | Pinned package using uv tool install when required by Raptor | Dedicated uv CLI environment | Wave 2 |
| Shannon | Exact-version Node package using local npm install | Node launcher plus Docker worker | Wave 3 |
| Numasec | Exact-version local npm package; source build uses Bun upstream | Node CLI; optional Docker execution | Wave 3 |
| CyberStrike | Exact-version local npm package | Node CLI and tool-specific agent environment | Wave 3 |
| PyRIT | Pinned source/project environment, uv lock where supplied | Dedicated Python environment; LLM endpoint optional until configured | Conditional Wave 4 |
| Hermes | Pinned source/project environment, core dependencies initially | Dedicated uv environment and separate execution VM/container | Conditional Wave 4 |
| WhatWaf | Pinned repo; inspect packaging/Python compatibility first | Dedicated uv venv or compatibility container | Optional Wave 4 |
| 10x-pentest | Pinned methodology repo | Skills/workflow files; host-client registration is a separate step | Wave 1 reference |
| Claude-BugHunter | Pinned skill/plugin repo | Claude Code skill host; no generic Python environment | Wave 1 reference |
| Pi | Pinned Node distribution/source according to upstream | Node/Bun build/runtime, not uv | Optional Wave 4 |
| DNS-history helper | Pinned script repository and reviewed dependencies | Bash/native executables | Optional Wave 4 |
| subfinder/httpx/nuclei/nmap/dig | Verify existing binaries; retain native installations | Go/native/Homebrew, not uv | Wave 1 verification |
| DNSDumpster/BuiltWith/Hardenize | Optional external browser services | No local environment; service use separately approved | No install |
| AdverserialAI/CyberKimi | Optional model endpoint configuration | Credentials/network settings, not a runtime package | No install |

Package names and upstream installation methods were checked against the official repositories. Source main can contain unreleased code; release/commit selection is a separate recorded decision.

## Wave 0 — Inventory and establish isolation

1. Confirm available disk space and architecture; choose a compatible supported Node runtime for each pinned Node package rather than assuming Node 25 compatibility.
2. Inspect uv configuration and any existing environment variables. Record the current executable paths before changes.
3. Create workspace-local tool/cache/bin locations. Set these variables only in a dedicated terminal/session script, initially avoiding permanent shell-profile changes.
4. Install uv-managed Python 3.12. This downloads a runtime and requires network access.
5. Verify Docker CLI/server and arm64 image availability before accepting Docker-dependent tools.

Planned commands:

```bash
PENTEST_ROOT='/Users/venky/work/preprod/waf/pentest-tools'
umask 077
mkdir -p "$PENTEST_ROOT/repos" "$PENTEST_ROOT/bin" "$PENTEST_ROOT/uv-tools" \
  "$PENTEST_ROOT/cache/uv" "$PENTEST_ROOT/python-envs" "$PENTEST_ROOT/node-tools" \
  "$PENTEST_ROOT/manifests" "$PENTEST_ROOT/logs" "$PENTEST_ROOT/lab" "$PENTEST_ROOT/secrets"
export UV_TOOL_DIR="$PENTEST_ROOT/uv-tools"
export UV_TOOL_BIN_DIR="$PENTEST_ROOT/bin"
export UV_CACHE_DIR="$PENTEST_ROOT/cache/uv"
export PATH="$PENTEST_ROOT/bin:$PATH"
uv --version
uv python install --no-bin 3.12
uv python find 3.12
docker version
```

Prefer persistent `uv tool install` environments for CLIs and committed project lockfiles for source projects. Avoid uvx in assessment runs when it would resolve a fresh package implicitly. [uv tool environment behavior](https://docs.astral.sh/uv/guides/tools/). Workspace-local directories use documented [uv environment settings](https://docs.astral.sh/uv/reference/environment/).

Acceptance: installation directories are recorded, Python 3.12 resolves, Docker requirements are known, and no global Python packages were changed.

## Wave 1 — Core tools and methodology repositories

Select exact released versions for wafw00f and ptai. Verify registry package ownership against the upstream repository before resolution. Set WAFW00F_VERSION and PTAI_VERSION to reviewed releases; the guards intentionally prevent execution with missing pins.

```bash
: "${WAFW00F_VERSION:?Set a reviewed released version}"
: "${PTAI_VERSION:?Set a reviewed released version}"
uv tool install --python 3.12 "wafw00f==$WAFW00F_VERSION"
uv tool install --python 3.12 "ptai==$PTAI_VERSION"
uv tool list
wafw00f --help
ptai --help
```

The Python tool environments are independent. Record their resolved dependency snapshots and interpreter paths; exact direct-package pins alone do not lock every transitive dependency. Use project-lock installs if full dependency reproducibility is required.

Clone 10x-pentest and Claude-BugHunter into repos/, check out reviewed refs, and record commit SHAs. Do not automatically register plugins or alter global Claude/Codex configuration. Pentest-AI MCP integration is also separate; inspect `ptai setup --mcp --dry-run` before deciding on client registration. [Pentest-AI setup](https://github.com/0xSteph/pentest-ai), [wafw00f](https://github.com/EnableSecurity/wafw00f), [10x-pentest](https://github.com/brovar/10x-pentest), [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter).

Acceptance: help commands succeed locally, environments and refs are recorded, and existing clients are unchanged. Do not run fingerprint probes on production as an installation test.

## Wave 2 — Strix and Raptor

Source checkouts provide visible provenance and committed locks. Inspect applicable repository instructions and package metadata before executing installation hooks. Set each REF to a reviewed tag/commit and do not reuse an existing directory without checking its ownership/state.

Example Strix installation:

```bash
: "${STRIX_REF:?Set a reviewed Strix tag or commit}"
git clone https://github.com/usestrix/strix.git "$PENTEST_ROOT/repos/strix"
git -C "$PENTEST_ROOT/repos/strix" checkout --detach "$STRIX_REF"
git -C "$PENTEST_ROOT/repos/strix" rev-parse HEAD
uv sync --project "$PENTEST_ROOT/repos/strix" --python 3.12 --locked --no-dev
uv run --project "$PENTEST_ROOT/repos/strix" --no-sync strix --help
```

Strix's Python distribution name is strix-agent, not strix; the CLI entry point is strix. Record Docker image tags/digests and test the worker in a disposable lab before declaring the complete runtime usable. [Strix](https://github.com/usestrix/strix).

Example Raptor installation:

```bash
: "${RAPTOR_REF:?Set a reviewed Raptor tag or commit}"
git clone https://github.com/gadievron/raptor.git "$PENTEST_ROOT/repos/raptor"
git -C "$PENTEST_ROOT/repos/raptor" checkout --detach "$RAPTOR_REF"
uv sync --project "$PENTEST_ROOT/repos/raptor" --python 3.12 --locked --no-dev
"$PENTEST_ROOT/repos/raptor/bin/raptor" --help
```

The installed Raptor v3.1.0 release has requirements.txt and no uv.lock; its dependencies were compiled into a separate hash-pinned requirements lock and synced into an isolated uv environment. The example above applies only to a checkout with a compatible uv.lock. Its session launcher also depends on Claude Code; install/verify that separately as a Node-hosted client. Semgrep should have its own pinned uv tool environment if needed; CodeQL is a separate native distribution with its own usage terms. Confirm the Raptor launcher's interpreter/dependency lookup before creating a wrapper so it does not accidentally use Homebrew Python. Install optional web/solver/cloud extras only for the planned workflow. [Raptor installation](https://github.com/gadievron/raptor).

Acceptance: locked environments build, CLI help works, required scanner/client binaries resolve, and Docker/agent lab calibration is separately demonstrated. A help command alone does not establish agent readiness.

## Wave 3 — Node tools alongside uv

uv cannot install these Node packages. Use separate local npm projects under node-tools/ so Node dependencies are also kept apart. Choose exact versions and validate package engine requirements first. Store package.json and package-lock.json; future restores use npm ci.

Example Numasec setup:

```bash
: "${NUMASEC_VERSION:?Set a reviewed released version}"
mkdir -p "$PENTEST_ROOT/node-tools/numasec"
cd "$PENTEST_ROOT/node-tools/numasec"
npm init -y
npm install --save-exact "numasec@$NUMASEC_VERSION"
./node_modules/.bin/numasec --help
```

Repeat the local-project pattern with @keygraph/shannon and @cyberstrike-io/cyberstrike using independently reviewed exact versions. Pin worker images for Shannon separately. Inspect npm lifecycle hooks before installation; do not assume --ignore-scripts will yield a functional runtime for every tool. Package installation and registration/provider setup are separate stages. [Numasec](https://github.com/FrancescoStabile/numasec), [Shannon](https://github.com/KeygraphHQ/shannon), [CyberStrike](https://github.com/CyberStrikeus/CyberStrike).

Acceptance: package lockfiles exist, Node engines match, help commands succeed, and Docker workers can start in the lab. Autonomous production testing remains outside installation acceptance.

## Wave 4 — Optional research and LLM stacks

- PyRIT: use the official Microsoft framework as the runtime; keep the course/notebook repo separate. Pick a compatible pinned checkout. If it has a committed uv.lock, use locked uv sync in its project. Otherwise create an independent .venv with uv, compile an exact-version requirements input into a pinned requirements lock, and install with uv pip sync. Add Jupyter only if notebooks are required. Verify local imports before configuring an LLM endpoint. Native dependencies such as ODBC may need separate platform setup. [PyRIT](https://github.com/microsoft/PyRIT).
- Hermes: use a pinned checkout and core dependencies initially. Prefer the supplied uv lock; otherwise follow the pinned repository's documented uv environment path. Inspect optional extras and native requirements rather than installing all extras on macOS. Verify hermes help/doctor, then configure only a dedicated execution environment. Messaging gateways and integrations remain disabled until requested. [Hermes](https://github.com/NousResearch/hermes-agent).
- WhatWaf: audit the pinned version's Python compatibility, setup metadata and requirements before choosing uv tool versus uv venv. The upstream reports limited maintenance; isolate compatibility failures rather than patching the shared environment. It is optional and not a prerequisite for the custom assessment. [WhatWaf](https://github.com/Ekultek/WhatWaf).
- Pi: use its official versioned Node distribution or reviewed source build; do not try to install it as a Python package. [Pi](https://github.com/earendil-works/pi).
- DNS-history helper: review the Bash entry point and dependencies before use. Candidate discovery does not authorize active testing of returned addresses.

Acceptance: optional runtime imports/help succeed, package versions and native dependencies are recorded, and each added capability has a specific assessment purpose.

## Wave 5 — Runtime readiness and local calibration

1. Produce an inventory with repo URL, checkout SHA, package version, Python/Node runtime, installation directory, lock hash, binary path, Docker image digest, smoke-test result and tool owner.
2. Distinguish installed, CLI works, provider configured, worker ready, lab calibrated and authorized for target. Never summarize all six as simply installed.
3. Launch an approved disposable local training app on loopback only; record the exact image digest, port, cleanup procedure and budget.
4. Run one tool at a time against that lab. Verify an expected finding with a negative control and independently replay its proof. Capture full tool-native artifacts outside the target source checkout.
5. Add wrappers under bin/ that resolve absolute project paths and use --no-sync or the appropriate locked runtime. They must not silently upgrade, install, register clients or launch background gateways during a test.
6. Integrate tool-native results with the assessment evidence directory only after validation. Keep tool provenance and candidate/verified labels intact.

Acceptance: at least the Wave 1 core is usable and one selected agent completes calibration. Resolve the existing altera.com benign 403 via logs before any expanded target campaign.

## Upgrade and rollback policy

Upgrade one tool at a time into a new versioned environment/check-out, rerun smoke/calibration checks, and update the manifest. Keep the previous environment until acceptance. Existing uv tool installations may be replaced when upgrading: preserve their package/dependency snapshot first or use versioned project environments for parallel versions. Uninstall only the workspace-owned environment after recording artifacts; do not remove Homebrew/system tools. Record licenses from the pinned code rather than relying on the older archive's blanket licensing descriptions.

## Recommended execution order

Wave 0 -> wafw00f/Pentest-AI and methodology references -> Strix plus lab calibration -> Raptor when source is available -> Node tools only for a demonstrated need -> optional LLM/custom-agent stacks.

Deliverables: a workspace-local install script, version/ref manifest, shell-session environment file, per-tool wrappers, install logs, readiness matrix and lab-calibration evidence. Installation scripts, pinned manifests, wrappers, logs and a readiness matrix are delivered in `../../pentest-tools/`. Lab-calibration evidence remains deferred under the user instruction not to run tools.
