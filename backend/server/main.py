# backend/server/main.py (Corrected)
from contextlib import asynccontextmanager
import os
import time
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from backend.security.request_context import (
    get_current_service,
    reset_current_role,
    reset_current_service,
    reset_current_tenant_id,
    set_current_role,
    set_current_service,
    set_current_tenant_id,
    sql_service_context,
)
from backend.server.middleware.body_size_limit import BodySizeLimitMiddleware

# --- Load Environment Variables ---
try:
    project_root = Path(__file__).resolve().parent.parent.parent
    dotenv_path = project_root / ".env"
    if dotenv_path.exists():
        load_dotenv(dotenv_path)
        print(f"INFO (main.py): Loaded environment variables from {dotenv_path}")
except Exception as e:
    print(f"WARNING (main.py): Could not load .env file. Falling back to defaults. Error: {e}")

# On Windows, joblib/loky may try to call the deprecated `wmic` to detect physical cores and emit noisy warnings.
if os.name == "nt" and "LOKY_MAX_CPU_COUNT" not in os.environ:
    try:
        os.environ["LOKY_MAX_CPU_COUNT"] = str(os.cpu_count() or 4)
    except Exception:
        pass


from backend.server.routers import (
    analysis as analysis_router,
    audit_router,
    auth as auth_router,
    configuration as configuration_router,
    defender_router,
    monitoring as monitoring_router,
    spam_analyzer_router,
    file_analyzer_router,
    dashboard_router,
    alerts_router,
    cases_router,
    investigation_router,
    websockets_router,
)
from backend.utils.logging_utils import setup_logger
from backend.services.query_analysis_service import QueryAnalysisService
from backend.services.spam_detection_service import SpamDetectionService
from backend.services.file_analysis_service import FileAnalysisService
from backend.services.file_scan_queue_factory import create_file_scan_queue_service
from backend.services.dashboard_service import DashboardService
from backend.services.alerts_service import AlertsService
from backend.services.incident_response_service import IncidentResponseService
from backend.services.defender_ai_service import DefenderAIService
from backend.services.case_management_service import CaseManagementService
from backend.services.investigation_service import InvestigationService
from backend.services.spam_autopipeline_service import SpamAutopipelineService
from backend.core.database import SessionLocal, create_db_tables, ensure_runtime_schema_compatibility
from backend.security.bootstrap_admin import ensure_bootstrap_admin
from backend.security.bootstrap_tenant import ensure_default_tenant
from backend.server.deps.auth import require_role
from backend.security.auth import _get_jwt_secret_key
from backend.utils.telemetry import telemetry

logger = setup_logger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await startup_event()
    try:
        yield
    finally:
        await shutdown_event()


app = FastAPI(
    title="AI-Powered Security Analysis API",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)
app.state.file_scan_queue_service = None
app.state.spam_autopipeline_service = None


_startup_ready: bool = False
_startup_error: Optional[str] = "startup_not_started"


def _set_startup_state(ready: bool, error: Optional[str] = None) -> None:
    global _startup_ready, _startup_error
    _startup_ready = ready
    _startup_error = error


# --- Middleware ---
def _parse_cors_origins() -> list[str]:
    raw = os.getenv("CORS_ORIGINS", "").strip()
    if not raw:
        return ["http://localhost:3000", "http://localhost:5173"]

    origins: list[str] = []
    for part in raw.split(","):
        origin = part.strip()
        if not origin or origin == "*":
            continue
        origins.append(origin)
    return origins or ["http://localhost:3000", "http://localhost:5173"]


app.add_middleware(BodySizeLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_parse_cors_origins(),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def _capture_service(request: Request, call_next):
    service = request.headers.get("X-Service-Name") or str(request.url.path)
    token = set_current_service(service)
    token_tenant = set_current_tenant_id(request.headers.get("X-Tenant-ID") or "")
    token_role = set_current_role("")
    started = time.perf_counter()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = int(getattr(response, "status_code", 500))
    finally:
        reset_current_service(token)
        reset_current_tenant_id(token_tenant)
        reset_current_role(token_role)
        latency_ms = (time.perf_counter() - started) * 1000.0
        telemetry.record_http(
            method=str(request.method or "GET"),
            path=str(request.url.path),
            status_code=status_code,
            latency_ms=latency_ms,
        )

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.url.path.startswith("/api/v1/auth") or request.url.path.startswith("/api/auth"):
        response.headers["Cache-Control"] = "no-store"
    return response


# --- API Routers ---
API_V1_PREFIX = "/api/v1"
API_LEGACY_PREFIX = "/api"

app.include_router(auth_router.router, prefix=f"{API_V1_PREFIX}/auth", tags=["Auth"])
app.include_router(
    analysis_router.router,
    prefix=f"{API_V1_PREFIX}/analyze-sql",
    tags=["SQL Analysis"],
    dependencies=[Depends(require_role("viewer"))],
)
app.include_router(
    spam_analyzer_router.router,
    prefix=f"{API_V1_PREFIX}/analyze-spam",
    tags=["Spam Analysis"],
    dependencies=[Depends(require_role("viewer"))],
)
app.include_router(
    file_analyzer_router.router,
    prefix=f"{API_V1_PREFIX}/analyze-file",
    tags=["File Analysis"],
    dependencies=[Depends(require_role("viewer"))],
)
app.include_router(
    dashboard_router.router,
    prefix=f"{API_V1_PREFIX}/dashboard",
    tags=["Dashboard"],
    dependencies=[Depends(require_role("viewer"))],
)
app.include_router(
    alerts_router.router,
    prefix=f"{API_V1_PREFIX}/alerts",
    tags=["Alerts"],
    dependencies=[Depends(require_role("analyst"))],
)
app.include_router(
    cases_router.router,
    prefix=f"{API_V1_PREFIX}/cases",
    tags=["Cases"],
    dependencies=[Depends(require_role("analyst"))],
)
app.include_router(
    investigation_router.router,
    prefix=f"{API_V1_PREFIX}/investigation",
    tags=["Investigation"],
    dependencies=[Depends(require_role("analyst"))],
)
app.include_router(
    defender_router.router,
    prefix=f"{API_V1_PREFIX}/defender",
    tags=["Defender AI"],
    dependencies=[Depends(require_role("reviewer"))],
)
app.include_router(
    monitoring_router.router,
    prefix=f"{API_V1_PREFIX}/monitoring",
    tags=["Monitoring"],
    dependencies=[Depends(require_role("reviewer"))],
)
app.include_router(
    audit_router.router,
    prefix=f"{API_V1_PREFIX}/audit",
    tags=["Audit"],
    dependencies=[Depends(require_role("admin"))],
)
app.include_router(
    configuration_router.router,
    prefix=f"{API_V1_PREFIX}/config",
    tags=["Configuration"],
    dependencies=[Depends(require_role("admin"))],
)
app.include_router(websockets_router.router, prefix=f"{API_V1_PREFIX}", tags=["WebSockets"])

app.include_router(auth_router.router, prefix=f"{API_LEGACY_PREFIX}/auth", tags=["Auth (legacy)"])
app.include_router(
    analysis_router.router,
    prefix=f"{API_LEGACY_PREFIX}/analyze-sql",
    tags=["SQL Analysis (legacy)"],
    dependencies=[Depends(require_role("viewer"))],
)
app.include_router(
    spam_analyzer_router.router,
    prefix=f"{API_LEGACY_PREFIX}/analyze-spam",
    tags=["Spam Analysis (legacy)"],
    dependencies=[Depends(require_role("viewer"))],
)
app.include_router(
    file_analyzer_router.router,
    prefix=f"{API_LEGACY_PREFIX}/analyze-file",
    tags=["File Analysis (legacy)"],
    dependencies=[Depends(require_role("viewer"))],
)
app.include_router(
    dashboard_router.router,
    prefix=f"{API_LEGACY_PREFIX}/dashboard",
    tags=["Dashboard (legacy)"],
    dependencies=[Depends(require_role("viewer"))],
)
app.include_router(
    alerts_router.router,
    prefix=f"{API_LEGACY_PREFIX}/alerts",
    tags=["Alerts (legacy)"],
    dependencies=[Depends(require_role("analyst"))],
)
app.include_router(
    cases_router.router,
    prefix=f"{API_LEGACY_PREFIX}/cases",
    tags=["Cases (legacy)"],
    dependencies=[Depends(require_role("analyst"))],
)
app.include_router(
    investigation_router.router,
    prefix=f"{API_LEGACY_PREFIX}/investigation",
    tags=["Investigation (legacy)"],
    dependencies=[Depends(require_role("analyst"))],
)
app.include_router(
    defender_router.router,
    prefix=f"{API_LEGACY_PREFIX}/defender",
    tags=["Defender AI (legacy)"],
    dependencies=[Depends(require_role("reviewer"))],
)
app.include_router(
    monitoring_router.router,
    prefix=f"{API_LEGACY_PREFIX}/monitoring",
    tags=["Monitoring (legacy)"],
    dependencies=[Depends(require_role("reviewer"))],
)
app.include_router(
    audit_router.router,
    prefix=f"{API_LEGACY_PREFIX}/audit",
    tags=["Audit (legacy)"],
    dependencies=[Depends(require_role("admin"))],
)
app.include_router(
    configuration_router.router,
    prefix=f"{API_LEGACY_PREFIX}/config",
    tags=["Configuration (legacy)"],
    dependencies=[Depends(require_role("admin"))],
)
app.include_router(websockets_router.router, prefix=f"{API_LEGACY_PREFIX}", tags=["WebSockets (legacy)"])


@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "Backend is healthy!" if _startup_ready else "Backend is starting up.",
        "ready": _startup_ready,
        "error": _startup_error,
    }


@app.get("/health/live", tags=["Health"])
async def health_liveness():
    return {"status": "alive"}


@app.get("/health/ready", tags=["Health"])
async def health_readiness():
    if not _startup_ready:
        raise HTTPException(status_code=503, detail={"status": "not_ready", "error": _startup_error or "startup_incomplete"})
    return {"status": "ready"}


if os.getenv("ENV", "").strip().lower() == "test":

    @app.get(
        "/api/v1/_test/current-service",
        tags=["Test"],
        dependencies=[Depends(require_role("viewer"))],
    )
    async def _test_current_service():
        return {"service": get_current_service()}


async def startup_event():
    _set_startup_state(False, "startup_in_progress")
    logger.info(f"'{app.title}' (Version: {app.version}) is starting up...")

    create_db_tables()
    # Startup bootstrap runs outside HTTP middleware. Assign an internal
    # bootstrap context so SQL enforcement remains active without treating fixed
    # ORM schema/bootstrap queries as anonymous unknown_service traffic.
    with sql_service_context("bootstrap_service", role="admin"):
        ensure_runtime_schema_compatibility()
        ensure_default_tenant()
        ensure_bootstrap_admin()

    try:
        _get_jwt_secret_key()

        main_file_dir = Path(__file__).parent.resolve()
        models_store_path = main_file_dir.parent / "data" / "models_store"
        yara_rules_path = main_file_dir.parent / "yara_rules" / "basic_rules.yar"

        logger.info("Initializing all services...")

        alerts_service = AlertsService()
        IncidentResponseService(alerts_service=alerts_service)
        defender_service = DefenderAIService()
        DashboardService()
        CaseManagementService()
        InvestigationService()

        query_service = QueryAnalysisService(
            anomaly_model_path=str(models_store_path / "anomaly_detection_model.joblib"),
            anomaly_scaler_path=str(models_store_path / "anomaly_query_scaler.joblib"),
            query_validation_model_path=str(models_store_path / "query_validation_model.joblib"),
            alerts_service=alerts_service,
        )

        spam_service = SpamDetectionService(
            model_path=str(models_store_path / "spam_detector_v1.joblib"),
            alerts_service=alerts_service,
        )

        file_service = FileAnalysisService(
            ml_model_path=str(models_store_path / "file_analyzer_v1.joblib"),
            yara_rules_path=str(yara_rules_path),
            alerts_service=alerts_service,
        )

        try:
            with sql_service_context("model_registry_service", role="admin"), SessionLocal() as db:
                activation = defender_service.activate_active_models(db=db)
            logger.info("Startup model activation from registry: %s", activation)
        except Exception as exc:
            logger.warning("Startup registry model activation failed; using bundled defaults: %s", exc)

        queue_service = create_file_scan_queue_service()
        await queue_service.start()
        app.state.file_scan_queue_service = queue_service

        try:
            spam_autopipeline_service = SpamAutopipelineService()
            await spam_autopipeline_service.start()
            app.state.spam_autopipeline_service = spam_autopipeline_service
        except Exception as exc:
            logger.warning("Spam autopipeline initialization failed; continuing without scheduler: %s", exc)

        startup_errors = []
        if not query_service.are_models_loaded():
            startup_errors.append("QueryAnalysisService models failed to load")
        if not spam_service.is_model_loaded():
            startup_errors.append("SpamDetectionService models failed to load")
        if not file_service.are_resources_loaded():
            startup_errors.append("FileAnalysisService resources failed to load")

        if startup_errors:
            msg = "; ".join(startup_errors)
            _set_startup_state(False, msg)
            logger.critical("Startup failed: %s", msg)
            raise RuntimeError(msg)

        _set_startup_state(True, None)
        logger.info("All services initialized successfully.")

    except Exception as exc:
        msg = str(exc)
        _set_startup_state(False, msg)
        logger.exception("Startup failed during service initialization")
        raise

    logger.info("Application startup sequence complete.")


async def shutdown_event():
    spam_autopipeline_service = getattr(app.state, "spam_autopipeline_service", None)
    if spam_autopipeline_service is not None:
        try:
            await spam_autopipeline_service.stop()
        except Exception as e:
            logger.error(f"Failed to stop spam autopipeline service cleanly: {e}", exc_info=True)

    queue_service = getattr(app.state, "file_scan_queue_service", None)
    if queue_service is not None:
        try:
            await queue_service.stop()
        except Exception as e:
            logger.error(f"Failed to stop file scan queue service cleanly: {e}", exc_info=True)


if __name__ == "__main__":
    import uvicorn

    logger.info("Starting application in debug mode using Uvicorn...")
    uvicorn.run("backend.server.main:app", host="0.0.0.0", port=8000, reload=True)
