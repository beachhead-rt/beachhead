```
 ▄▄▄▄   ▓█████ ▄▄▄       ▄████▄   ██░ ██  ██░ ██ ▓█████ ▄▄▄      ▓█████▄
▓█████▄ ▓█   ▀▒████▄    ▒██▀ ▀█  ▓██░ ██▒▓██░ ██▒▓█   ▀▒████▄    ▒██▀ ██▌
▒██▒ ▄██▒███  ▒██  ▀█▄  ▒▓█    ▄ ▒██▀▀██░▒██▀▀██░▒███  ▒██  ▀█▄  ░██   █▌
▒██░█▀  ▒▓█  ▄░██▄▄▄▄██ ▒▓▓▄ ▄██▒░▓█ ░██ ░▓█ ░██ ▒▓█  ▄░██▄▄▄▄██ ░▓█▄   ▌
░▓█  ▀█▓░▒████▒▓█   ▓██▒▒ ▓███▀ ░░▓█▒░██▓░▓█▒░██▓░▒████▒▓█   ▓██▒░▒████▓
░▒▓███▀▒░░ ▒░ ░▒▒   ▓▒█░░ ░▒ ▒  ░ ▒ ░░▒░▒ ▒ ░░▒░▒░░ ▒░ ░▒▒   ▓▒█░ ▒▒▓  ▒
▒░▒   ░  ░ ░  ░ ▒   ▒▒ ░  ░  ▒    ▒ ░▒░ ░ ▒ ░▒░ ░ ░ ░  ░ ▒   ▒▒ ░ ░ ▒  ▒
 ░    ░    ░    ░   ▒   ░         ░  ░░ ░ ░  ░░ ░   ░    ░   ▒    ░ ░  ░
 ░         ░  ░     ░  ░░ ░       ░  ░  ░ ░  ░  ░   ░  ░     ░  ░   ░
      ░                 ░                                         ░
```

# Beachhead

**Authorized Azure DevOps post-exploitation framework for red team engagements.**

Beachhead is a CLI- and TUI-first framework built for one job: **what to do once you already have valid credentials or a token.** It assumes a foothold and focuses on ADO enumeration, credential harvesting, attack-path analysis, and scoped exploitation, not initial access or credential theft.

> **Authorized use only.** Beachhead operates exclusively within a signed engagement scope config. Scope enforcement, read-by-default behavior, audit logging, and artifact cleanup tracking are enforced in code, not left to operator discipline.

---

## Features

- **20 modules** across 4 phases: enumerate (9), analyze (3), harvest (5), exploit (3)
- **ADO-focused**: deep enumeration of pipelines, service connections, repos, feeds, permissions, extensions, service hooks, agent pools, and variable groups
- **Credential harvesting**: cred-engine-powered secret detection (59 patterns) across repos, wikis, build logs, work items, PR comments, and pipeline variables
- **Attack path analysis**: 9 offline attack-path types derived from collected data (service connection lateral movement, Key Vault access, self-hosted agent execution, credential exposure, branch policy bypass, feed poisoning, permission escalation, service hook exfiltration, extension privilege abuse)
- **Exploitation**: classic and YAML pipeline variable dump with log-masking bypass, service connection credential extraction (Azure RM SP + Docker Registry), retention lease release, `--confirm` gate, and automatic artifact cleanup
- **Time-based filtering**: `--since` flag on CLI commands and time-filter dropdown in the TUI Modules view; all enumerate, harvest, and exploit modules filter ADO projects and repos by recent activity, reducing noise and API calls during time-scoped engagements
- **Textual TUI**: 8 views (Dashboard, Modules, Runs, Resources, Paths, Findings, Credentials, Audit) with command palette (Ctrl+P), drill-down detail screens, module search, time-filter dropdown, and reactive engagement bar
- **Headless CLI**: full parity with the TUI for scripting; `bh modules` lists all registered modules
- **SQLite datastore**: the contract between modules and surfaces; collection and analysis are decoupled and reproducible offline
- **OPSEC by design**: scope guardrail, rate limiting with jitter, append-only audit log, artifact cleanup with teardown gate

---

## Requirements

- **Python 3.12+**
- **[uv](https://docs.astral.sh/uv/)** (package manager)
- **ADO Personal Access Token** with appropriate scopes for the target organization
- **Engagement scope config**: an untracked YAML file defining the authorized boundary (see [Configuration](#configuration))

---

## Installation

```bash
# Clone the repository
git clone <repo-url> beachhead
cd beachhead

# Install all dependencies
uv sync

# Activate the virtual environment
source .venv/bin/activate   # or .venv\Scripts\activate on Windows

# Verify installation
bh --version
```

### Optional: fast data tables

For large enumeration result sets (10K+ rows), install the Apache Arrow-backed DataTable:

```bash
uv sync --extra fast
```

---

## Configuration

**No config? No problem.** Run any `bh` command and the guided setup walks you through it:

```bash
bh engage status
# → No engagement config found. Let's set up a new engagement.
# → Prompts for: engagement name, ADO orgs, ADO PAT
# → Writes config, caches PAT, creates store, ready to enumerate
```

Or create the config manually (gitignored):

### Minimal (ADO-only engagement)

```yaml
# engagement.local.yaml
engagement: "ACME-2026-Q2"
ado_organizations: ["acme-eng"]
```

Only `engagement` and at least one scope dimension (typically `ado_organizations`) are required. Everything else is optional and defaults sensibly:
- `authorization_ref` defaults to `""`
- `window` defaults to now + 90 days

### Full (all optional fields)

```yaml
# engagement.local.yaml
engagement: "ACME-2026-Q2"
authorization_ref: "SOW-1234 / RoE signed 2026-04-01"
window:
  start: 2026-04-15T00:00:00Z
  end:   2026-04-30T23:59:59Z
ado_organizations: ["acme-eng"]
```

**No scope config = refuses to run.** There is no "no-scope" mode.

---

## Usage

### Authentication

```bash
# Store an ADO Personal Access Token (read from stdin, never the command line)
bh auth ado-pat
# Or pipe it:  echo "$ADO_PAT" | bh auth ado-pat

# Check cached token status
bh auth status

# Clear cached tokens
bh auth clear
bh auth clear ado    # clear only ADO tokens
```

### Quick start

```bash
# 1. Run any command; guided setup handles config + PAT in one flow
bh enumerate run ado_pipelines
# → Creates engagement config, collects ADO PAT, creates store, runs the module

# 2. Run more enumeration
bh enumerate run ado_service_connections
bh enumerate run ado_repos
bh enumerate run ado_permissions

# 3. Harvest credentials
bh harvest run ado_credential_scan
bh harvest run ado_wiki_scan

# 4. Analyze attack paths (offline, over the store)
bh analyze run ado_attack_paths

# 5. Launch TUI to explore results
bh tui
```

### TUI (Textual interface)

```bash
bh tui
```

8 views over the engagement data:

| # | View | Content |
|---|------|---------|
| 1 | Dashboard | Stats panel, teardown readiness, recent runs |
| 2 | Modules | Searchable catalog, run button with live output |
| 3 | Runs | Run history |
| 4 | Resources | Collected ADO resources |
| 5 | Paths | Attack paths with score filtering |
| 6 | Findings | Findings with severity filtering |
| 7 | Credentials | Harvested credentials from the secure credential store |
| 8 | Audit | Append-only audit log |

Key features:
- **Command palette** (Ctrl+P): fuzzy search for views, actions, and filters
- **Drill-down**: Enter on attack paths or findings opens detail screens with actionable next steps
- **Module runner**: run modules directly from the TUI with streaming output and time-filter dropdown (24h / 7d / 30d / this month / this year)
- **Engagement bar**: persistent status showing engagement name, ADO orgs, window, run count, cleanup state
- **Live refresh**: views reload on tab switch; dashboard updates after module runs
- **Keyboard navigation**: `1`-`8` switch views, `r` refreshes, `t` toggles tabs, `q` quits

### Headless CLI

#### Module operations

```bash
# List all registered modules
bh modules
bh modules ado                    # filter by name/summary/ATT&CK ID
bh modules --phase enumerate      # show only one phase

# List modules in a phase
bh enumerate list
bh analyze list
bh harvest list
bh exploit list

# Run a specific module
bh enumerate run ado_pipelines
bh harvest run ado_credential_scan
bh analyze run ado_attack_paths

# Run with a time filter (only projects/repos active since the cutoff)
bh enumerate run ado_pipelines --since 7d
bh harvest run ado_credential_scan --since 30d

# Run all modules in a phase
bh enumerate run-all

# Exploit operations require --confirm
bh exploit run ado_pipeline_vardump --confirm
bh exploit run ado_yaml_pipeline_vardump --confirm
bh exploit run ado_service_connection_extract --confirm
```

#### Read commands (query the local store)

```bash
bh status              # engagement summary
bh paths               # derived attack paths
bh findings            # collection findings (--kind, --severity)
bh audit               # append-only audit log (--run <id> to filter)
```

All read commands support `--json` for structured output.

#### Engagement lifecycle

```bash
bh engage status       # detailed engagement + teardown readiness
bh engage export       # export report to .json or .md
bh engage teardown     # verify cleanup queue empty (fails if pending artifacts)
```

### Global options

| Option | Env var | Description |
|---|---|---|
| `--store`, `-s` | `BEACHHEAD_STORE` | Path to the SQLite store (default: `./beachhead.sqlite`) |
| `--config`, `-c` | | Path to engagement config (else env/default) |
| `--since` | | Time filter for module runs: `24h`, `7d`, `30d`, `this-month`, `this-year`, or ISO datetime |
| `--version` | | Show version and exit |

---

## Modules

### Enumerate (9 modules): ADO resource discovery

| Module | Description | MITRE ATT&CK |
|---|---|---|
| `ado_pipelines` | YAML pipelines, classic build/release definitions; flags plaintext secret variables | T1059.009 |
| `ado_service_connections` | Service endpoints; flags subscription-level Azure RM scope and shared connections | T1078.004 |
| `ado_agent_pools` | Agent pools and agents; flags self-hosted pools and sensitive capabilities | T1526 |
| `ado_variable_groups` | Variable groups; flags Key Vault links and plaintext secrets | T1552.001 |
| `ado_repos` | Repos, branches, policies, PRs; flags missing branch policies | T1213.003 |
| `ado_feeds` | Packaging feeds and packages; flags public upstream sources (dependency confusion) | T1195.002 |
| `ado_permissions` | Security namespaces and ACLs; decodes permission bitmasks with severity classification | T1069.003 |
| `ado_service_hooks` | Service hook subscriptions; flags insecure (HTTP) URLs and external targets | T1102.002 |
| `ado_extensions` | Installed marketplace extensions; flags high-privilege third-party extensions | T1176 |

### Analyze (3 modules): offline analysis

| Module | Description | MITRE ATT&CK |
|---|---|---|
| `ado_attack_paths` | Derives 9 attack path types from store data: service connection lateral movement, Key Vault access, self-hosted agent execution, credential exposure, branch policy bypass, feed poisoning, permission escalation, service hook exfiltration, extension privilege abuse | T1078.004 |
| `collected_resources` | Displays collected resources from the store grouped by type (offline, no API calls) | T1580 |
| `discovered_credentials` | Displays harvested credentials from the secure credential store (offline, no API calls) | T1552.001 |

### Harvest (5 modules): credential discovery

| Module | Description | MITRE ATT&CK |
|---|---|---|
| `ado_credential_scan` | ALM Search credential detection across repos and work items (cred-engine, 59 patterns) | T1552.001 |
| `ado_wiki_scan` | Wiki page credential search via ALM Wiki Search | T1552.001 |
| `ado_pipeline_log_scan` | Build log scanning for secret scrubbing failures (base64-encoded, bearer tokens, API keys) | T1552.001 |
| `ado_pr_scan` | Pull request comment credential scanning (cred-engine) | T1552.001 |
| `ado_variable_scan` | Pipeline variable credential classification (cred-engine variable classifier) | T1552.001 |

### Exploit (3 modules): confirmation-gated operations

| Module | Description | MITRE ATT&CK |
|---|---|---|
| `ado_pipeline_vardump` | Clones a classic (designer) pipeline with a variable-dump task to extract masked secret variables; bypasses ADO log masking via base64+reverse encoding. Deletes build run (releasing retention leases) and cloned definition on cleanup. Requires `--confirm`. | T1552.001, T1059.001 |
| `ado_yaml_pipeline_vardump` | Creates a temporary branch in the pipeline's source repo, injects a variable-dump YAML step, queues a run, and extracts masked secrets from the build log. Deletes build run (releasing retention leases) and temporary branch on cleanup. Requires `--confirm`. Only supports Azure Repos Git-backed YAML pipelines. | T1552.001, T1059.001 |
| `ado_service_connection_extract` | Injects a task referencing a target service connection into a YAML pipeline via a temporary branch. Supports Azure RM (extracts SP client ID, client secret, tenant ID via `AzureCLI@2`) and Docker Registry (extracts username/password via `Docker@2` login + config.json read). Deletes build run and temporary branch on cleanup. Requires `--confirm`. | T1552.001, T1059.001 |

---

## Architecture

```
ADO PAT ──> core/auth ──> clients (az | ado_search)
                                │  (every call via core/scope + core/audit)
                                ▼
                          modules/<phase>
                                │  normalize + write
                                ▼
                    ┌─── core/store (SQLite WAL) ───┐
                    │                               │
                    ▼                               ▼
            core/secret_store              TUI / CLI (read)
            (*.secrets.sqlite)                      │
                    │                               │
                analyze (read) ──> attack paths ───>┘
```

- **Collection and analysis are decoupled by the store.** Module runs are the only thing that touches ADO; everything downstream runs offline.
- **Modules write normalized rows through the store access layer**, never raw API JSON, never their own SQLite connections.
- **Discovered credentials are encrypted** in a separate `*.secrets.sqlite` database protected by a passphrase. The main store holds redacted findings for attack-path analysis; the credential store holds the encrypted originals for offline operator access via `bh analyze run discovered_credentials`.

---

## Project layout

```
src/beachhead/
  core/
    auth/          # token acquire/refresh; ADO PAT
    clients/       # az_client, ado_search: shared retry/throttle/audit
    store/         # SQLite models + access layer + migrations
    config.py      # engagement + scope config loading + guided bootstrap
    scope.py       # authorization/scope guardrails (all calls pass through here)
    audit.py       # structured operator-action logging
    cred_bridge.py # credential bridge (findings -> secret store)
    secret_store.py # encrypted credential store (*.secrets.sqlite)
    export.py      # engagement report builder (JSON + Markdown)
    loader.py      # module registry via entry-point discovery
    runner.py      # module execution orchestrator
    boot.py        # full client/store wiring for module runs
    timefilter.py  # --since / time-filter parsing and row filtering
    errors.py      # typed error hierarchy
  modules/         # post-ex operations; each implements the common module interface
    enumerate/     # ADO resource discovery                              [read]
    analyze/       # attack-path analysis over the store (no API calls)  [read]
    harvest/       # credential discovery                                [read]
    exploit/       # scoped exploitation (3 modules)          [confirmation-gated]
  tui/             # Textual app: 8 views + command palette + drill-down detail screens
    commands.py    # command palette provider
    widgets.py     # engagement bar
    views/         # dashboard, modules, runs, resources, paths, findings, credentials, audit
  cli/             # Typer app: read commands + phase groups + auth + engage
tests/
```

---

## Safety & OPSEC

These are enforced in code, not by convention:

- **Scope enforcement**: every API/CLI call routes through `core/scope.py`. Out-of-scope targets hard-fail. No scope config = refuses to run.
- **Read-by-default**: enumerate, analyze, and harvest are read-only. Exploit operations require interactive `--confirm`.
- **Audit logging**: every operation (operator, action, target, timestamp) is recorded in an append-only log.
- **Automatic cleanup**: exploit modules delete their artifacts (build runs, cloned definitions, temporary branches) in `finally` blocks. Retention leases are released before build deletion. Failures are audited and flagged for manual cleanup.
- **Rate limiting**: all clients apply token-bucket limiting and jitter.
- **Redaction**: the main store and logs never contain cleartext secrets. Findings store redacted references. Credential values are encrypted in the separate passphrase-protected `*.secrets.sqlite` credential store.
- **No hardcoded secrets**: tokens, organization names, and client identifiers live only in the untracked scope config and the gitignored token cache.

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
