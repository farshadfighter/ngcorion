# NGCorion

NGCorion is a security hardening and compliance platform for an organisation's
own infrastructure. It keeps an inventory of assets, audits them against CIS
benchmarks and vendor hardening guides, applies the fixes it can (with backups
and verification), and tracks what is left: vulnerabilities (CVE and
distribution advisories), risk, remediation, reports and alerts.

| Area | What it does |
|---|---|
| Assets | Inventory, asset types and icons, discovery (nmap), software inventory, change history, topology |
| Auditing | CIS/vendor benchmark audits of 17 target families (below), scheduled audits |
| Hardening | Single fixes and "Harden All" with parameters, preview, backup, verification and rollback |
| Vulnerabilities | CVE database (NVD, CISA KEV, EPSS; online or signed offline packages) and distribution advisories (OSV) |
| Risk & remediation | Asset risk scores, remediation items with SLAs, risk acceptance workflow |
| Operations | NOC (SNMP polling, interface metrics), alerts and notification channels, reports (PDF/Excel, scheduled, signed) |
| Platform | Users with per-module permissions, audit logs, license, system backup/restore, system settings, Persian and English UI |

Audited targets: Cisco IOS, FortiGate, Linux (Ubuntu, Debian, RHEL family),
Windows Server, Apache, MongoDB, MSSQL, Active Directory, Windows DNS Server,
Windows DHCP Server, IIS 10, Docker, Kubernetes, MySQL 8, VMware ESXi, NGINX
and Sophos Firewall.

## Repository layout

```
app/                  FastAPI backend (Python 3.13)
  main.py             application entry point: middleware, routers, background tasks
  core/               configuration, auth, security helpers, SSH/TLS pinning, license client
  middleware/         license enforcement, security headers
  models/             SQLAlchemy models (one file per domain)
  modules/<area>/     one package per feature: router, service, schemas, engine
  modules/benchmark/  the shared audit/hardening engine used by the newer target modules
alembic/              database migrations (the only way the schema changes)
front/                React 18 + Vite frontend (Redux Toolkit, react-router, i18next)
tests/                pytest suite (unit, integration against Postgres, emulators of devices)
docs/                 architecture, developer guide, security notes
deploy/, traefik/     production deployment (docker compose, reverse proxy, license server stack)
```

## Quick start (development)

Requirements: Python 3.13 with [uv](https://docs.astral.sh/uv/), Node 22,
PostgreSQL 16, and nmap for discovery.

```bash
# backend
uv sync --group dev
export DATABASE_URL=postgresql+psycopg://netease:<password>@localhost/netease_db
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
export LICENSE_SERVER_URL=https://<your license server>
uv run alembic upgrade head
uv run uvicorn app.main:app --reload --port 8000

# frontend (second terminal)
cd front
npm ci
VITE_BACKEND_URL=http://127.0.0.1:8000 npm run dev      # http://localhost:5173
```

The first administrator is created with `scripts/init_db.py`.

With Docker: `docker compose up -d --build` runs Traefik, Postgres and the
backend (which serves the built frontend from `front/dist`); see
`docker-compose.yml` for the required environment.

## Checks

The same checks run in CI (`.github/workflows/ci.yml`) on every push:

```bash
uv run pytest -q                       # backend, needs Postgres (DATABASE_URL)
cd front && npm run lint && npm test && npm run i18n:check && npm run build
```

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how the pieces fit together.
- [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md): conventions, and step-by-step
  recipes (new API endpoint, new page, new audit/hardening target).
- [SECURITY.md](SECURITY.md): reporting, dependency checks, accepted exceptions.
- [docs/SSH_HOST_KEY_VERIFICATION.md](docs/SSH_HOST_KEY_VERIFICATION.md): how device
  host keys and TLS certificates are pinned.
- [docs/SECURITY_REMEDIATION_CHECKLIST.md](docs/SECURITY_REMEDIATION_CHECKLIST.md):
  the findings of the first security review and how each was closed.
