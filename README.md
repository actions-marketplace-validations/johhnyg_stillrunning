# stillrunning

> Supply chain security for developers and AI coding agents.
> Active protection against 200,000+ verified malicious packages from 8 threat intelligence sources.

[![PyPI version](https://img.shields.io/pypi/v/stillrunning)](https://pypi.org/project/stillrunning/)
![Protected by stillrunning](https://stillrunning.io/badge/protected)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-blue)

## What's new in v2.8

- **Async scan endpoint** — `POST /api/scan/async` for non-blocking scans
- **Version-aware AI cache** — cache keyed by `(package, version)` tuple
- **Source tracking** — every blocklist entry records where it came from
- **OSV.dev bulk ingestion** — 222k malicious packages from PyPI and npm
- **Registry liveness checking** — marks packages removed from registries

## What it protects against

| Threat Class | Example |
|-------------|---------|
| Typosquats | `reqeusts`, `colourma`, `djanga` |
| Malicious packages | Pre/post-install scripts stealing credentials |
| Prompt injection | README-based attacks targeting AI agents |
| Dependency confusion | Internal package names registered publicly |
| Hallucinated packages | AI-suggested packages that don't exist (then claimed) |

## Supported package managers

| Package Manager | Status |
|----------------|--------|
| pip / pip3 | Intercepted |
| python3 -m pip | Intercepted |
| uv | Intercepted |
| poetry | Intercepted |
| pdm | Intercepted |
| pipenv | Intercepted |
| conda | Intercepted |
| pixi | Intercepted |
| npm | Intercepted |
| bun | Intercepted |
| pnpm | Intercepted |
| requirements.txt | Scanned |
| import statement | Blocked (via hook) |

## Quick start

```bash
pip install stillrunning
stillrunning --setup              # 3-minute setup wizard
stillrunning scan <package>       # One-shot scan
stillrunning --install-hook       # Always-on import protection
```

## Import protection

```python
import stillrunning.hook  # Blocks malicious imports at runtime
```

## AI agent integrations

Works with: Claude Code, Cursor, Devin, Replit, GitHub Copilot, Windsurf, Aider

Setup: [stillrunning.io/agent-setup](https://stillrunning.io/agent-setup)

### Claude Code skill

```bash
claude mcp add stillrunning -- stillrunning mcp
```

Or add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "stillrunning": {
      "type": "url",
      "url": "https://stillrunning.io/mcp"
    }
  }
}
```

### GitHub Actions

Add supply chain security to your CI/CD pipeline:

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  stillrunning:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: johhnyg/stillrunning@v1
        with:
          requirements: requirements.txt
          # Optional: fail on suspicious packages too
          # fail-on-suspicious: true
```

For npm projects:

```yaml
      - uses: johhnyg/stillrunning@v1
        with:
          package-json: package.json
          package-lock: package-lock.json
```

## Security Advisories

Browse the full threat database: [stillrunning.io/security-advisories](https://stillrunning.io/security-advisories)

RSS feed: [stillrunning.io/security-advisories/rss.xml](https://stillrunning.io/security-advisories/rss.xml)

## Privacy

Heartbeats contain: command name, version, OS, anonymous UUID, timestamp.
**No code, file paths, or package names are sent.**

Disable: `STILLRUNNING_NO_TELEMETRY=1` or `--no-telemetry` flag.

## Configuration

| Variable | Purpose |
|----------|---------|
| `STILLRUNNING_NO_TELEMETRY=1` | Disable heartbeat |
| `BLOCKLIST_MAX_AGE_DAYS=730` | Max age for blocklist entries (default 2 years) |
| `STILLRUNNING_TOKEN` | API token (enables import-time checks) |
| `STILLRUNNING_FAIL_CLOSED=1` | Wrappers stop the install when a package could not be checked |

Token file: `~/.stillrunning/stillrunning.yaml` (`token: ...`)

## Commands

```bash
stillrunning --setup          # Setup wizard
stillrunning --doctor         # Health check
stillrunning --install-hook   # Enable always-on import protection
stillrunning --autonomous     # CI/CD mode
stillrunning --allow <pkg>    # Allow a blocked package
stillrunning scan <pkg>       # One-shot scan
stillrunning whitelist add <pkg>    # Add to whitelist
stillrunning whitelist list         # Show whitelist
```

## Pricing

<!-- BEGIN:tier-table -->
| Tier | Price | Scans/day | Machines | Dashboard |
|------|-------|-----------|----------|-----------|
| Free | Free | 10 | 1 | No |
| Personal | $9/mo | 100 | 1 | No |
| Basic | $29/mo | Unlimited | 3 | Yes |
| Ai | $49/mo | Unlimited | Unlimited | Yes |
| Enterprise | $499/mo | Unlimited | Unlimited | Yes |
<!-- END:tier-table -->

<!-- BEGIN:feature-list -->
**Personal** ($9/mo)
- Everything in Free
- 100 scans/day
- Telegram + email alerts
- Email support

**Basic** ($29/mo)
- Everything in Personal
- yourname.stillrunning.io dashboard
- Monday weekly reports
- Uptime milestone alerts
- File integrity tripwire
- 3 machines

**Ai** ($49/mo)
- Everything in Basic
- AI crash diagnosis
- Reply to alerts - AI answers
- Crash pattern detection
- AI Agent Integrity Monitor
- Unlimited machines
- Priority support

**Enterprise** ($499/mo)
- Everything in AI
- Dedicated account manager
- Custom integrations
- SLA guarantee
- On-premises option
<!-- END:feature-list -->

## Badge

```markdown
![Protected by stillrunning](https://stillrunning.io/badge/protected)
```

## Links

- [stillrunning.io](https://stillrunning.io)
- [Security Advisories](https://stillrunning.io/security-advisories)
- [Agent Setup](https://stillrunning.io/agent-setup)
- [@bit_bot9000](https://x.com/bit_bot9000)

## License

MIT License

Patent Pending — US Provisional Application filed April 12, 2026
