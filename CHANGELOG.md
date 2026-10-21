# Changelog

## 2.13.7 — October 21, 2026 (Session 129)

**Import-time protection works again; `scan`, the import hook and the wrappers no longer report CLEAN on a failure**

### Fixed
- **Import hook never scanned.** It POSTed to `/api/check-package` (GET-only →
  HTTP 405 on every call). It now sends a GET and acts on **BLOCKED**, the
  verdict the API returns (it previously only acted on DANGEROUS). A missing
  verdict is UNKNOWN, never CLEAN.
- **Import hook no longer spends the free tier.** Remote import-time checks run
  only with an API token (`STILLRUNNING_TOKEN` or `token:` in
  `~/.stillrunning/stillrunning.yaml`); without one it warns once. It looks up
  the installed *distribution* (not every module name) and remembers each
  answered result for 24 h per machine (a 429/503 is retried next time).
  Mapping imports to distributions needs Python 3.10+; on 3.8/3.9 import-time
  checks are skipped with a one-time warning (install-time checks still run).
- **`stillrunning scan` exit codes are honest.** The threat API is consulted
  before the registry (a delisted malicious package is BLOCKED, not "not
  found"). API errors are no longer reported as CLEAN:
  `0` not on the blocklist (not a clean bill of health) · `10` BLOCKED ·
  `11` SUSPICIOUS · `12` daily quota exhausted · `1` could not check
  (offline / server error / stale data) · `3` not on the registry · `2` timeout.
- **pip / npm / conda wrappers** block only on a real verdict (10, 11). If the
  check could not run they print a loud *"NOT checked — installing anyway"*;
  set `STILLRUNNING_FAIL_CLOSED=1` to stop the install instead.
- `intercept.py`: a missing verdict is UNKNOWN, never CLEAN.

### Known issue
- `scan-manifest` (AI scan via `/api/scan`) can still print CLEAN when the AI
  scan returns nothing (no token / quota / tier). Fix planned for 2.13.8.

### Upgrade note
Shell wrappers are installed files: after `pip install -U stillrunning`, run
`stillrunning shell-install` once to update them.

## Unreleased — August 18, 2026 (Session 122)

**GitHub Action + CI hardening**

### Added
- **GitHub Action** (`johhnyg/stillrunning@v1`) — CI/CD supply chain scanning via
  `action.yml` + `scan.py`. Scans `requirements.txt` (default) and/or
  `package.json`/`package-lock.json`, fails the build on DANGEROUS packages
  (optionally SUSPICIOUS with `fail-on-suspicious: true`). Outputs: `status`,
  `dangerous-count`, `suspicious-count`, `report`. Optional `token` input enables
  AI scanning of unknown packages.

  ```yaml
  - uses: johhnyg/stillrunning@v1
    with:
      requirements: requirements.txt
  ```

- **ASCII security block banner** — `scan.py` renders a bold red shield banner
  ("SUPPLY-CHAIN SECURITY BLOCK") when malicious packages are detected, so blocks
  are unmissable in CI logs.

### Fixed
- **pip/npm shim subcommand handling** — the wrappers hardcoded `install`
  regardless of the command actually run, breaking `pip download` entirely and
  rewriting `npm i` / `npm add` semantics. Both shims now capture the original
  subcommand and pass it through.

## v2.13.3 — June 12, 2026

**Telemetry heartbeats actually reach the server**

### Fixed
- **Anonymous heartbeats were silently 403'd.** stillrunning.io sits behind
  Cloudflare, which blocks the default `Python-urllib/x.y` User-Agent. The
  heartbeat client sent no User-Agent, so every `install`/`active`/`intercept`/`cli`
  heartbeat was rejected and the exception swallowed — no agent telemetry had ever
  landed. All three request sites (`_send_heartbeat`, `send_intercept_event`,
  `send_cli_ping`) now send `User-Agent: stillrunning/{version}`. Verified: a clean
  container install now lands a heartbeat (HTTP 200).

## v2.13.2 — June 11, 2026

**npm scanning actually works**

### Fixed
- **`stillrunning scan --npm`** — the npm wrapper called `scan <pkg> --npm`, but the
  flag never existed; combined with `set -e` the wrapper failed closed and blocked
  EVERY npm install. scan now checks the npm registry (scoped `@org/pkg` names
  supported), the npm section of the threat feed, and passes `ecosystem=npm` to the
  check-package API.
- **Hardcoded blocklist normalization** — dash-named entries (`pino-debugger`,
  `dev-log-core`, ...) could never match because only the input was normalized to
  underscores. Both sides normalize now.
- **`axios` delegated to the threat feed** — covered by MAL-2026-2307 (malicious
  0.30.4/1.14.1) with proper withdrawal lifecycle instead of a permanent hardcode.

### Added
- **`@anthropic-ai/*` trusted-scope skip** in the npm wrapper template.

---


## v2.11.0 — May 2, 2026

**Single source of truth + bypass route coverage**

### Added
- **features.json** — version, tiers, verify_checks, last_session in one file
- **`/api/version`** — serves features.json with 5-minute cache
- **scripts/sync-version.py** — syncs version to pyproject.toml and cli.py
- **scripts/regen-readme.py** — regenerates tier table from features.json
- **Venv auto-enable** — shell-install now installs sitecustomize.py automatically
- **Conda hook** — conda_hook.sh wraps `conda install/create`

### Security
- **Closes CVE-2026-31431 gaps #1 (venv) and #5 (conda)**

---

## v2.10.0 — May 2, 2026

**CVE-2026-31431 gap fixes — shell auto-activation**

### Added
- **`stillrunning shell-install`** — auto-activate hooks on shell init (bash/zsh/profile)
- **`stillrunning shell-uninstall`** — remove shell hooks
- **`stillrunning status`** — show status of all protection layers
- **Wrapper scripts** — `~/.stillrunning/bin/pip`, `pip3`, `npm` intercept installs
- **Idempotent rc updates** — reinstall won't duplicate lines in shell config

### Security
- **Closes CVE-2026-31431 audit gap #4** — hooks now activate without manual `source activate.sh`

---

## v2.9.0 — April 25, 2026

**Customer experience polish + CLI standardization**

### Added
- **pricing.py** — single source of truth for all tier pricing
- **Welcome email idempotency** — Stripe webhook retries no longer send duplicate emails
- **Telegram wizard** — `/dash/{subdomain}/telegram` for in-dashboard bot setup
- **Resend-welcome endpoint** — admin can resend welcome emails via API

### Changed
- All pricing references now use `pricing.py` (landing, /pricing, emails)
- Welcome emails now use `alerts@stillrunning.io` From header

### Breaking
- **Exit codes standardized** across all CLI tools:
  - 0 = CLEAN, 1 = ERROR, 2 = USAGE
  - 10 = BLOCKED, 11 = SUSPICIOUS, 12 = RATE_LIMITED, 13 = WITHDRAWN

---

## v2.8.0 — April 25, 2026

**Async scan endpoint + version-aware AI cache**

### Added
- **Async scan endpoint** — `POST /api/scan/async` returns immediately with job_id, poll `/api/scan/status/{job_id}` for results
- **Version-aware AI cache** — cache key is now `(package_name, version)` instead of just `package_name`
- **cache_clear_older_than(days)** — maintenance function to purge old cache entries
- **resolve_latest_version()** — resolves "latest" to actual version from PyPI/npm

### Changed
- Async jobs auto-expire after 1 hour (TTL)
- Legacy cache entries marked `version="unknown"` for re-review on next check

### Breaking
- **Exit codes standardized** across the stillrunning family:
  - 0 = CLEAN (operation succeeded, no threats)
  - 1 = Generic error (network failure, internal bug)
  - 2 = Usage error (bad arguments, missing file)
  - 10 = BLOCKED (confirmed malicious package)
  - 11 = SUSPICIOUS (AI flagged, not confirmed)
  - 12 = RATE_LIMITED (free tier exhausted)
- CI pipelines that assumed exit 1 = block must update to check for exit 10

---

## v2.7.0 — April 25, 2026

**Source tracking + curated blocklist**

### Added
- **Source tracking** — each blocked package shows advisory source (OSV, GitHub, NVD, etc.)
- **Advisory ID linking** — direct links to original security advisories
- **Curated blocklist** — 200,000+ packages from 8 threat intelligence sources

### Changed
- `/security-advisories` page shows source metadata badges
- Blocklist entries include `source` and `advisory_id` fields

---

## v2.6.0 — April 24, 2026

**Fix OSV.dev integration — now ingests ~220,000 malicious packages**

### Fixed
- **OSV.dev API query was broken** — malformed `/v1/query` call returned 0 results
- Now uses bulk GCS download (`osv-vulnerabilities.storage.googleapis.com`) instead

### Added
- **osv_bulk.py** — server-side bulk ingestion of MAL-* advisories
- **222,873 malicious packages** now blocked (10,962 PyPI + 211,911 npm)
- Nightly cron refresh at 03:00 UTC

### Changed
- Blocklist lookup remains O(1) (dict-based, not list)
- Blocklist served from `/api/blocklist` — package size unchanged (76KB wheel)

### Followups (v2.7.0)
- Version-range blocking (currently blocks all versions via `["any"]`)

---

## v2.5.0 — April 24, 2026

**Completeness release — all deferred items from v2.4.0 shipped**

### Added
- **Virtual environment interception** via sitecustomize.py (survives `source .venv/bin/activate`)
- **`stillrunning venv-install`** command to enable venv persistence
- **`stillrunning venv-uninstall`** command to cleanly remove venv integration
- **Debug logging infrastructure** — set STILLRUNNING_DEBUG=1 for verbose output

### Changed
- **Exception handlers audited** — critical handlers now log to debug instead of silent pass
- **VERSION constant** bumped to 2.5.0 in cli.py

### Internal
- **stillrunning/venv_hook.py** — lightweight hook for sitecustomize.py integration
- **12 new tests** for venv persistence and logging infrastructure
- **40 total tests** passing

### Deferred
- A2 (cache version-aware): Requires dashboard.py changes — documented in v2.6.0-followups.md
- A5 (async scan endpoint): Requires dashboard.py changes — documented in v2.6.0-followups.md
- F (GitHub Action): Separate repo — documented in v2.6.0-followups.md
- A4 (exception audit): ~20 handlers updated, remaining documented for future work

---

## v2.4.0 — April 24, 2026

**Refinement release — closes HIGH-severity gaps from product audit**

### Added
- **Manifest parsing** for requirements.txt, pyproject.toml, Pipfile, package.json, environment.yml, pixi.toml
- **Interception for poetry, pdm, pipenv, conda, pixi, bun, pnpm** — all major package managers now covered
- **`stillrunning scan-manifest`** CLI command — check all packages in a manifest file before install
- **`pip install -r requirements.txt`** now scans each package (previously bypassed entirely)

### Fixed
- **Hardcoded /root/my-app/.env path** in hook.py — now uses XDG-compliant ~/.stillrunning directory
- **Editable installs** (`pip install -e .`) no longer erroneously blocked or flagged
- **Git/URL dependencies** correctly skipped (can't be checked, shouldn't block)

### Internal
- **stillrunning/manifest.py** — shared manifest parser for all package managers
- **28 new tests** covering manifest parsing, package manager support, and intercept behavior
- **MANAGER_ECOSYSTEM mapping** — proper ecosystem detection for all package managers

---

## v2.3.0 — April 24, 2026

**Critical correctness fixes**

- **Fix:** `/api/check-package` now checks blocklist (was returning UNKNOWN for blocked packages)
- **Fix:** `stillrunning scan <package>` command now works (was documented but not implemented)
- **Fix:** `uv pip install` and `uv add` are now intercepted (previously silent bypass)
- **Fix:** Namespace packages (`azure.storage.blob`) now checked against blocklist
- **Security:** All four fixes address cases where the tool appeared to work but didn't protect users

---

## v2.1.0 — April 19, 2026

**Anonymous telemetry (opt-in)**

- **Heartbeat** — sends anonymous ping to stillrunning.io every 6 hours
- **Setup prompt** — Y/n question after Telegram config
- **Privacy-first** — no email, IP, or log content; just random UUID
- **Disable anytime** — set `telemetry: false` in stillrunning.yaml

**Payload:** machine_id, agent_version, os_type, uptime_hours, process_count

This helps us understand how many agents are actually running. Previously we had 1,500 PyPI downloads but zero visibility into active usage.

---

## v2.0.0 — April 15, 2026

**Import hook + MCP integration**

- **Python import hook** — blocks malicious imports before execution
  - `import stillrunning.hook` to activate
  - `stillrunning --install-hook` for always-on protection
  - Async design: cache check is instant, background scanning for unknown packages
  - Flag on next import if background scan finds issues
- **MCP server** — Claude Code integration
  - `check_package` tool for pre-install verification
  - Add to Claude Code config for automatic package checking
  - Rate limited by tier (100/day AI, unlimited Enterprise)
- **Interactive approvals** — Telegram allow/deny with one tap
  - UNKNOWN packages: blocked pending 60s approval
  - SUSPICIOUS packages: blocked with research link
  - DANGEROUS packages: hard block, no override
  - `/allow_{token}` and `/deny_{token}` commands
- **Coverage page** — honest documentation of what is/isn't blocked
- **Developer docs** — terminal-style integration guide at /developers
- **GitHub Action v2** — import scanning + hash verification

**Breaking changes:**
- Version bump to 2.0.0 — new major version for import hook feature

## v1.9.0 — April 14, 2026

**Tiered feature gating**

- **Tier system**: Personal ($9), Basic ($29), AI ($49), Enterprise ($499)
- Token validation on startup — validates against stillrunning.io API
- Server-side AI package review — Claude Haiku analysis (AI tier+)
- 1-hour token cache with 24-hour offline grace period
- Rate limits: 100 scans/day (AI), 500 (Team), unlimited (Enterprise)
- Feature gates: tripwire, file_integrity, honeypot require Basic+
- New `features.py` module — tier validation and feature checking
- `stillrunning.yaml` now requires `token` field for premium features

**Pricing tiers:**
- Personal: process monitor, restart, Telegram alerts
- Basic: + file integrity, tripwire, honeypot
- AI: + AI package review (server-side)
- Enterprise: + unlimited scans, SIEM, SSO, compliance

## v1.5.0 — April 2026

**Security layer — supply chain protection**

- `stillrunning guard` — always-on security daemon with auto-learning whitelist (214 processes)
- `stillrunning scan` — static analysis: AST parser, entropy detection, pkl inspector
- npm/pip intercept — blocks poisoned packages before install (hash check + static scan)
- Advisor upgrade — Sonnet executor + Opus advisor pattern for AI operations
- Chrome extension scaffold — green/red status dot in browser
- `/scan` route — customer file upload threat scanner (free tier 10/day)
- North Korea supply chain attack response — 1,700+ malicious packages blocked

## v1.4.0 — April 2026

- Email alerts — no Telegram required
- Two-way email — reply to alerts, AI answers from live data
- Monday weekly report — automatic every week
- Uptime milestone alerts — 7, 30, 60, 90, 365 days
- Threat feed — new CVEs auto-pushed to every agent
- Crash pattern AI — detects root cause after 5 events
- `--diagnose` — instant health check on demand
- `--reconfigure` — change alert settings anytime
- Docker support
- Raspberry Pi confirmed support
- Windows PowerShell installer

## v1.3.0 — March 2026

- Shield security system
- Multi-server support
- Telegram two-way control
- AI crash diagnosis (AI tier)
- Daily health audit (AI tier)

## v1.2.0 — February 2026

- Live dashboard at yourname.stillrunning.io
- Process auto-detection (screen, systemd, PM2)
- Resource monitoring (CPU, memory, disk)
- Log rotation

## v1.1.0 — January 2026

- Initial release
- Process watchdog
- Telegram alerts
- Auto-restart
