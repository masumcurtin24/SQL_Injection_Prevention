# backend/server/routers/analysis.py
from fastapi import APIRouter, Depends, HTTPException, Body
from typing import Any
from sqlalchemy.orm import Session

# --- Project Module Imports ---
# This structure ensures that the necessary modules are found.
try:
    from backend.core.database import get_db 
    from backend.server.deps.tenant import TenantContext, get_tenant_context
    from backend.server.schemas.requests import SQLQueryRequest, SQLPrecisionEvaluationRequest
    from backend.server.schemas.responses import AnalysisResponse, SQLPrecisionEvaluationResponse
    from backend.services.query_analysis_service import QueryAnalysisService
    from backend.utils.logging_utils import setup_logger
except ImportError: 
    # This fallback is for local development and testing.
    print("INFO: SQL Analysis router using fallback imports...")
    import sys
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir_path = os.path.join(current_dir, '..', '..')
    if backend_dir_path not in sys.path:
        sys.path.insert(0, backend_dir_path)
    from core.database import get_db
    from server.deps.tenant import TenantContext, get_tenant_context
    from server.schemas.requests import SQLQueryRequest, SQLPrecisionEvaluationRequest
    from server.schemas.responses import AnalysisResponse, SQLPrecisionEvaluationResponse
    from services.query_analysis_service import QueryAnalysisService
    from utils.logging_utils import setup_logger

logger = setup_logger(__name__)
router = APIRouter()

# --- THE CRITICAL FIX: CORRECTED DEPENDENCY INJECTOR ---
# The faulty module-level instantiation has been REMOVED.
# This function is now the single point of access to the service.

def get_query_analysis_service() -> QueryAnalysisService:
    """
    Dependency injector that retrieves the single, globally-initialized 
    instance of QueryAnalysisService that was created at application startup.
    It verifies the service and its models are ready before allowing access.
    """
    try:
        # Retrieve the singleton instance that was correctly configured in `main.py`.
        # This is the core of the fix.
        service_instance = QueryAnalysisService.get_instance()
        
        # Verify that the models within the service were loaded successfully.
        if not service_instance.are_models_loaded():
            logger.error("QueryAnalysisService instance is available, but its critical models failed to load.")
            raise HTTPException(status_code=503, detail="SQL analysis models are not available.")
            
        return service_instance
        
    except RuntimeError as e:
        # This will catch the error if this endpoint is called before the service has been initialized.
        logger.critical(f"FATAL: {e}. The service was requested before the application's startup event completed.")
        raise HTTPException(status_code=503, detail="SQL Analysis Service is not initialized.")

@router.post(
    "/query", 
    response_model=AnalysisResponse,
    summary="Analyze a SQL Query (Anomaly & NLP)",
    description="Submits a SQL query for analysis by both anomaly detection and NLP validation."
)
async def analyze_sql_query_endpoint(
    request_body: SQLQueryRequest = Body(..., examples=[{"query": "SELECT user, host FROM mysql.user;"}]),
    db: Session = Depends(get_db), 
    # FastAPI will call `get_query_analysis_service` to get the service instance for this request.
    service: QueryAnalysisService = Depends(get_query_analysis_service),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> AnalysisResponse:
    
    query_to_analyze = request_body.query
    logger.info(f"API endpoint /query received request for SQL analysis: '{query_to_analyze[:100]}...'")

    if not query_to_analyze or not query_to_analyze.strip():
        raise HTTPException(status_code=400, detail="Query string cannot be empty.")
    
    # The dependency injector (`get_query_analysis_service`) now handles all checks for initialization
    # and model availability, so no further checks are needed here.
    
    try:
        analysis_result_dict = service.analyze_query(
            db=db,
            sql_query=query_to_analyze,
            tenant_id=tenant_ctx.tenant_id,
        )
        return AnalysisResponse(**analysis_result_dict)
    except Exception as e:
        logger.error(f"Unexpected error during SQL query analysis for '{query_to_analyze[:100]}...': {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="An unexpected internal error occurred during analysis.")


@router.post(
    "/precision-eval",
    response_model=SQLPrecisionEvaluationResponse,
    summary="Evaluate SQL Precision v2 on Labeled Samples",
    description="Runs calibrated SQL detection against labeled samples and returns precision/recall/F1 metrics.",
)
async def evaluate_sql_precision_endpoint(
    request_body: SQLPrecisionEvaluationRequest = Body(
        ...,
        examples=[
            {
                "samples": [
                    {"query": "SELECT * FROM users WHERE id = 1", "expected_label": "benign"},
                    {"query": "SELECT * FROM users WHERE id = 1 OR 1=1 --", "expected_label": "malicious"},
                ],
                "include_predictions": False,
                "max_examples": 20,
            }
        ],
    ),
    service: QueryAnalysisService = Depends(get_query_analysis_service),
) -> SQLPrecisionEvaluationResponse:
    if not request_body.samples:
        raise HTTPException(status_code=400, detail="At least one sample is required.")
    try:
        payload = service.evaluate_precision_dataset(
            samples=[s.model_dump() for s in request_body.samples],
            include_predictions=bool(request_body.include_predictions),
            max_examples=int(request_body.max_examples),
        )
        return SQLPrecisionEvaluationResponse(**payload)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error during SQL precision evaluation: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="An unexpected internal error occurred during SQL evaluation.")
