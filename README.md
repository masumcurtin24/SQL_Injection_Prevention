# AI-Powered Middleware Security Platform

COMP6016 Masters Project - Group 07

This repository contains a full-stack prototype for analysing and reducing common web-application security risks. The platform combines SQL injection analysis and enforcement, file-upload security checks, spam/phishing detection, dashboard monitoring, alerts, policy controls, and supporting benchmark evidence.

The project was developed as a Curtin University COMP6016 group project. It is an academic prototype, not a production security gateway.

## Project Scope

The implemented prototype covers:

- SQL injection analysis and prevention support.
- File upload security analysis using static inspection, file metadata checks, YARA rules, archive/OOXML checks, and scoring logic.
- Spam and phishing analysis using classical machine-learning models, URL/domain indicators, rule-based checks, and explainable score output.
- Dashboard views for security activity, trends, alerts, and live updates.
- Policy and alert management features.
- Multi-tenant and role-aware application flow where supported by the backend and frontend.
- Benchmark and validation artefacts for the main security domains.

The prototype does not claim full enterprise deployment, durable quarantine, real sandbox detonation, completed email gateway enforcement, or production SIEM integration unless those external systems are connected.

## Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| Frontend | React, TypeScript, Vite, Tailwind CSS | Browser interface and security dashboards |
| Backend | Python, FastAPI | REST APIs, WebSocket updates, service orchestration |
| Data access | SQLAlchemy, Alembic | Database models and schema migrations |
| Storage | SQLite by default | Local development and demonstration database |
| Security analysis | Python services, scikit-learn/joblib models, YARA rules | SQL, file, and spam/phishing analysis |
| Containers | Docker Compose, Nginx | Reproducible frontend/backend deployment |
| Testing | Pytest, benchmark scripts, frontend build checks | Regression and validation evidence |

## Repository Structure

```text
.
|-- backend/
|   |-- core/                 Database models and shared backend setup
|   |-- server/               FastAPI app, routers, schemas, middleware, WebSockets
|   |-- services/             SQL, file, spam, dashboard, alert, policy, and case services
|   |-- security/             SQL enforcement and security policy logic
|   |-- tests/                Backend unit and integration tests
|   |-- data/                 Models, corpora, benchmark outputs, and runtime evidence
|   |-- yara_rules/           File-analysis YARA rules
|   `-- alembic/              Database migrations
|-- frontend/
|   `-- src/                  React application pages, components, hooks, and API client
|-- docker/                   Nginx reverse-proxy configuration
|-- Dockerfile.backend        FastAPI runtime image
|-- Dockerfile.frontend       React build and Nginx runtime image
|-- docker-compose.yml        Full-stack local container deployment
|-- integration/              DVWA and external integration helpers
|-- tools/                    Utility scripts for lab integration
|-- docs/                     Benchmark, scoring, and governance notes
|-- figures/                  Architecture diagrams and visual evidence
`-- .github/                  Continuous-integration workflows
```

## Main Features

### SQL Analysis and Prevention

- Analyses submitted SQL text for injection indicators.
- Uses normalisation, rules, scoring, and model-backed checks where model artefacts are present.
- Provides risk score, severity, explanation, and recommended action.
- Includes SQLAlchemy-level enforcement support through `backend/security/sql_enforcer.py`.
- Supports configurable enforcement modes such as monitor, block critical, and block high.

### File Security Analysis

- Accepts uploaded files through the backend API and frontend interface.
- Checks file type, extension, MIME information, size, YARA matches, archive structure, OOXML content, macro indicators, and suspicious embedded behaviour.
- Produces a structured verdict, risk score, matched evidence, and recommended action.
- Static macro detection is implemented, but macro execution and full sandbox detonation are outside the current prototype.

### Spam and Phishing Detection

- Analyses email subject, body, sender, links, and supporting metadata.
- Combines model scoring, URL/domain indicators, suspicious TLD checks, blocklist support, and rule-based phishing indicators.
- Returns a risk score, classification, explanation, and score breakdown.
- Grey-zone results should be treated as review-required decisions, not automatic proof of maliciousness.

### Dashboard, Alerts, Policies, and Roles

- Dashboard endpoints summarise recent activity, category counts, severity distribution, live events, and trend data.
- Alerts can be listed, viewed, acknowledged, and broadcast to the frontend through WebSockets.
- Policy and role-aware features are present in the project flow, with limitations documented in the report and requirements checklist.

## Setup

### Prerequisites

- Python 3.13 or later.
- Node.js 20 or later.
- PowerShell, Command Prompt, or a Unix-like terminal.
- Docker Desktop or Docker Engine with Compose, if using the container setup.

### Docker Setup

The root Compose file builds the React frontend and FastAPI backend, runs database migrations, stores the SQLite database in a named volume, and serves the application through Nginx on one port.

Create a local environment file:

```powershell
Copy-Item .env.example .env
```

Replace `BOOTSTRAP_ADMIN_PASSWORD` and `JWT_SECRET_KEY` in `.env` before starting. The JWT secret must contain at least 32 characters. A strong value can be generated with:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Build and start the stack:

```powershell
docker compose up --build --detach
docker compose ps
```

Open the application at `http://localhost:3000`. The backend health endpoint is available through the same origin at `http://localhost:3000/health/ready`; API and WebSocket traffic is proxied internally to the backend container.

View logs or stop the stack with:

```powershell
docker compose logs --follow
docker compose down
```

The `backend-runtime` volume retains the SQLite database across ordinary container restarts and `docker compose down`.

For a provider-neutral single-VPS deployment with automatic HTTPS, persistent
Caddy state, loopback-only direct frontend access, and backup/update/rollback
procedures, see [Single-VPS production deployment](docs/single-vps-deployment.md).

### Backend Setup

From the repository root:

```powershell
python -m venv backend/.venv
backend/.venv/Scripts/Activate.ps1
pip install -r backend/requirements.txt
```

Create or update `.env` in the repository root. For local SQLite development:

```text
DATABASE_URL=sqlite:///./sql_app.db
LOG_LEVEL=INFO
```

Run database migrations:

```powershell
python -m alembic -c backend/alembic.ini upgrade head
```

Start the backend:

```powershell
uvicorn backend.server.main:app --host 0.0.0.0 --port 8000
```

Check the health endpoint:

```text
http://localhost:8000/health
```

### Frontend Setup

```powershell
cd frontend
npm install
npm run dev
```

The frontend normally runs at:

```text
http://localhost:5173
```

The frontend API client expects the backend to be available at port `8000` unless changed in the frontend environment configuration.

## Validation Commands

Backend critical subset:

```powershell
python scripts/run_backend_critical_subset.py
```

Runtime baseline:

```powershell
python scripts/verify_runtime_baseline.py
```

Runtime baseline with frontend check:

```powershell
python scripts/verify_runtime_baseline.py --include-frontend
```

Frontend production build:

```powershell
cd frontend
npm run build
```

Benchmark harness:

```powershell
python backend/scripts/build_evaluation_corpus.py --domain all --strict
python backend/scripts/run_benchmark_harness.py --domain all --disable-transformer --strict-gate
```

## Selected API Endpoints

| Feature | Endpoint |
|---|---|
| Health check | `GET /health` |
| SQL analysis | `POST /api/v1/analyze-sql/query` |
| File analysis | `POST /api/v1/analyze-file/file` |
| File queue submit | `POST /api/v1/analyze-file/file/queue` |
| File queue status | `GET /api/v1/analyze-file/file/jobs/{job_id}` |
| Spam/phishing analysis | `POST /api/v1/analyze-spam/email` |
| Spam feedback | `POST /api/v1/analyze-spam/feedback` |
| Dashboard summary | `GET /api/v1/dashboard/summary-stats` |
| Alerts | `GET /api/v1/alerts` |
| Acknowledge alert | `PATCH /api/v1/alerts/{id}/acknowledge` |
| WebSocket updates | `ws://localhost:8000/api/v1/ws/updates` |

Browser WebSocket clients send access and step-up credentials through the
`Sec-WebSocket-Protocol` handshake header, not the URL. Query-string token
authentication is deprecated and disabled by default because URLs are commonly
captured in access logs. `WS_ALLOW_LEGACY_QUERY_AUTH=true` is available only as
a temporary migration aid.

## Models and Data

The backend expects model artefacts under `backend/data/models_store/`. Important local artefacts include:

- `anomaly_detection_model.joblib`
- `anomaly_query_scaler.joblib`
- `query_validation_model.joblib`
- `spam_detector_v1.joblib`
- `file_analyzer_v1.joblib`

If a model is missing, the affected service may return an error or fall back to limited heuristic behaviour. This is documented as a prototype limitation.

Benchmark corpora and evidence are stored under:

- `backend/data/corpus/`
- `backend/data/benchmarks/`
- `backend/data/benchmarks/runs/final_2026_05_06/`

Raw datasets, historical training runs, local runtime data, and academic submission artefacts are intentionally excluded from the public repository. See `.gitignore` for the publication boundary.

## Validation Evidence

Key public validation files:

- `docs/benchmarks/final_benchmark_summary.md`
- `docs/benchmarks/calibration_summary.md`
- `docs/score_formula_reference.md`
- `backend/data/benchmarks/runs/final_2026_05_06/`

Latest recorded validation evidence in the report package:

- Backend validation: 268 passed, 53 warnings.
- Frontend validation: `npm run build` passed.

## Configuration Notes

Important environment variables include:

- `DATABASE_URL`: database connection string.
- `LOG_LEVEL`: backend logging level.
- `SQL_ENFORCEMENT_MODE`: `off`, `monitor`, `block_high`, or `block_critical`.
- `SQL_ALLOWLIST_PATTERNS`: optional SQL allowlist patterns.
- `SPAM_FINAL_THRESHOLD`: spam/phishing final decision threshold.
- `REPUTATION_BLOCKLIST_PATH`: path to domain or URL blocklist.
- `FILE_ANALYSIS_STRICT_INIT`: controls whether missing file-analysis dependencies fail startup.
- `FILE_SCAN_QUEUE_BACKEND`: `memory` or `redis`.
- `FILE_DYNAMIC_ENABLE`: enables external dynamic file-analysis workflow when available.

Do not commit `.env`, local databases, virtual environments, `node_modules`, or private API keys.

## DVWA Lab

The project includes a DVWA integration lab under:

```text
integration/dvwa-compose/
```

Start the lab from that folder:

```powershell
docker compose up --build
```

The DVWA lab is an experimental integration scaffold and still requires local instrumentation and authenticated analyzer requests. It is separate from the supported root full-stack Compose setup. DVWA is intentionally vulnerable: run it only in an isolated local lab, never expose it publicly, and never use it for unauthorised testing against external systems.

## Known Limitations

- The current platform is a prototype for academic evaluation.
- SQLite is used by default for local demonstration.
- Full production authentication hardening, SIEM integration, gateway blocking, durable quarantine, and cloud deployment are outside the confirmed implementation scope.
- File dynamic-analysis provider support requires an external provider configuration.
- Evaluation quality depends on the available corpora, model artefacts, and benchmark runs.
- Some dashboard and policy features are implemented as prototype workflow support rather than complete enterprise governance.

## Maintenance Notes

For a new maintainer:

1. Read this README and the technical notes under `docs/`.
2. Install backend and frontend dependencies.
3. Run migrations with `python -m alembic -c backend/alembic.ini upgrade head`.
4. Run `python -m pytest -q` and `npm run build` from `frontend/`.
5. Start backend and frontend locally.
6. Review `backend/data/benchmarks/runs/final_2026_05_06/` before quoting any metric.

