# backend/services/file_analysis_service.py (Corrected and Complete)
import os
import io
import zipfile
import joblib
import yara
import magic
import uuid
import logging
import re
import hashlib
from typing import Optional, Any, Dict, List, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse
from fastapi import UploadFile
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import json
import asyncio
from pathlib import Path
try:
    import yaml  # type: ignore
except Exception:
    yaml = None

# --- Project Module Imports ---
from backend.utils.logging_utils import setup_logger
from backend.services.alerts_service import AlertsService
from backend.services.ai_reliability_service import assess_ai_reliability
from backend.services.explainability_contract import complete_explainability_contract
from backend.services.incident_response_service import IncidentResponseService
from backend.server.schemas.responses import (
    FileAnalysisDetails, FileTypeValidationResult,
    MalwareScanResult, MLScanResult,
    FileAnalysisOverallAssessment, Alert as AlertSchema,
    XAIExplanation, XAIExplanationEvidence, XAIExplanationTraceStep,
    FileStructuredVerdict, FileVerdictEvidenceItem, FileVerdictStage, FileIOC, FileDynamicAnalysisState,
    MacroDefenseResult,
)
from backend.core.models import DEFAULT_TENANT_ID, FileAnalysisLog as FileAnalysisLogModel
from backend.server.websockets import manager
from backend.services.file_dynamic.providers import (
    BaseDynamicAnalysisProvider,
    DynamicEvidenceItem,
    DynamicIOCItem,
    DynamicResultPayload,
    create_dynamic_analysis_provider,
)

logger = setup_logger(__name__)

# --- Configuration Constants ---
ALLOWED_MIME_TYPES = {
    # Images & text
    "image/jpeg", "image/png", "text/plain", "text/html", "application/xhtml+xml",
    # Documents
    "application/pdf",
    "application/msword",  # legacy .doc (OLE)
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    # Office Open XML (ZIP-based)
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",  # .docx
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",        # .xlsx
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",# .pptx
    # Macro-enabled OOXML
    "application/vnd.ms-word.document.macroEnabled.12",       # .docm
    "application/vnd.ms-excel.sheet.macroEnabled.12",         # .xlsm
    "application/vnd.ms-powerpoint.presentation.macroEnabled.12", # .pptm
    # Archives
    "application/zip",
}
MAX_FILE_SIZE_MB = 10
TEXT_BASED_MIME_TYPES_FOR_ML = {
    "text/plain", "text/csv", "application/javascript", "text/html", "application/xml", "text/x-python",
}

# Archive scanning limits (defense-in-depth against zip bombs)
MAX_ARCHIVE_FILES = 200
MAX_ARCHIVE_DEPTH = 3
MAX_ARCHIVE_TOTAL_UNCOMPRESSED_MB = 100
MAX_ENTRY_SIZE_MB = 25
IOC_TEXT_SCAN_LIMIT_BYTES = 1024 * 1024

# Policy knob for PoC YARA handling:
#  - 'suspicious' (default): mark PoC indicators as Suspicious unless dangerous exec markers are present
#  - 'malicious_on_danger': escalate to Malicious only when dangerous exec markers are present
POC_YARA_POLICY = os.getenv("POC_YARA_POLICY", "suspicious").strip().lower()

# Allowed domains for payment/exfil to reduce noise in web skimmer detection
ALLOWED_PAYMENT_DOMAINS = set(
    d.strip().lower() for d in os.getenv(
        "ALLOWED_PAYMENT_DOMAINS",
        "stripe.com,paypal.com,braintreepayments.com,authorize.net,squareup.com"
    ).split(",") if d.strip()
)
ALLOWED_EXFIL_DOMAINS = set(
    d.strip().lower() for d in os.getenv("ALLOWED_EXFIL_DOMAINS", "").split(",") if d.strip()
)

MALICIOUS_YARA_THREAT_LEVELS = set(
    x.strip().lower() for x in os.getenv("YARA_MALICIOUS_THREAT_LEVELS", "high,critical").split(",") if x.strip()
)
SUSPICIOUS_YARA_THREAT_LEVELS = set(
    x.strip().lower() for x in os.getenv("YARA_SUSPICIOUS_THREAT_LEVELS", "medium,low").split(",") if x.strip()
)


def _load_file_detection_policy_from_yaml() -> None:
    """Optional YAML policy override for file detection tuning."""
    global POC_YARA_POLICY
    global MAX_ARCHIVE_FILES, MAX_ARCHIVE_DEPTH, MAX_ARCHIVE_TOTAL_UNCOMPRESSED_MB, MAX_ENTRY_SIZE_MB
    global MALICIOUS_YARA_THREAT_LEVELS, SUSPICIOUS_YARA_THREAT_LEVELS
    global ALLOWED_PAYMENT_DOMAINS, ALLOWED_EXFIL_DOMAINS

    if yaml is None:
        return
    try:
        policy_path = Path(__file__).resolve().parents[1] / "security" / "prevention_rules.yml"
        if not policy_path.exists():
            return
        with open(policy_path, "r", encoding="utf-8") as fp:
            data = yaml.safe_load(fp) or {}
        if not isinstance(data, dict):
            return
        section = data.get("file_detection") or {}
        if not isinstance(section, dict):
            return

        poc_policy = str(section.get("poc_policy") or "").strip().lower()
        if poc_policy in {"suspicious", "malicious_on_danger", "block_on_danger"}:
            POC_YARA_POLICY = poc_policy

        archive = section.get("archive_limits") or {}
        if isinstance(archive, dict):
            try:
                if archive.get("max_files") is not None:
                    MAX_ARCHIVE_FILES = int(archive.get("max_files"))
                if archive.get("max_depth") is not None:
                    MAX_ARCHIVE_DEPTH = int(archive.get("max_depth"))
                if archive.get("max_uncompressed_mb") is not None:
                    MAX_ARCHIVE_TOTAL_UNCOMPRESSED_MB = int(archive.get("max_uncompressed_mb"))
                if archive.get("max_entry_mb") is not None:
                    MAX_ENTRY_SIZE_MB = int(archive.get("max_entry_mb"))
            except Exception:
                pass

        yara_policy = section.get("yara") or {}
        if isinstance(yara_policy, dict):
            mal = yara_policy.get("malicious_threat_levels")
            sus = yara_policy.get("suspicious_threat_levels")
            if isinstance(mal, list):
                vals = set(str(x).strip().lower() for x in mal if str(x).strip())
                if vals:
                    MALICIOUS_YARA_THREAT_LEVELS = vals
            if isinstance(sus, list):
                vals = set(str(x).strip().lower() for x in sus if str(x).strip())
                if vals:
                    SUSPICIOUS_YARA_THREAT_LEVELS = vals

        allow = section.get("allow_domains") or {}
        if isinstance(allow, dict):
            pay = allow.get("payment")
            exf = allow.get("exfil")
            if isinstance(pay, list):
                ALLOWED_PAYMENT_DOMAINS = set(str(x).strip().lower() for x in pay if str(x).strip())
            if isinstance(exf, list):
                ALLOWED_EXFIL_DOMAINS = set(str(x).strip().lower() for x in exf if str(x).strip())
    except Exception as e:
        logger.warning(f"Failed to load file_detection policy from YAML: {e}")


_load_file_detection_policy_from_yaml()

_URL_RE = re.compile(r"(?i)\bhttps?://[^\s\"'<>]+")
_DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b")
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
_HASH_RE = re.compile(r"(?i)\b[a-f0-9]{32,128}\b")
_WIN_PATH_RE = re.compile(r"(?i)\b[a-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]+\b")
_UNIX_PATH_RE = re.compile(r"(?i)\b/(?:[a-z0-9._-]+/)+[a-z0-9._-]+\b")
_COMMAND_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("powershell", re.compile(r"(?i)\bpowershell(?:\.exe)?\b[^\r\n]{0,240}")),
    ("regsvr32", re.compile(r"(?i)\bregsvr32\b[^\r\n]{0,240}")),
    ("curl", re.compile(r"(?i)\bcurl\b[^\r\n]{0,240}")),
    ("wget", re.compile(r"(?i)\bwget\b[^\r\n]{0,240}")),
    ("netcat", re.compile(r"(?i)\bnc\b[^\r\n]{0,240}")),
    ("shell", re.compile(r"(?i)\b(?:bash|sh|cmd(?:\.exe)?)\b[^\r\n]{0,240}")),
]
REMOTE_SHELL_EXEC_MARKERS = {"powershell_socket_shell", "netcat_reverse_shell"}
HARD_EXEC_MARKERS = {
    "powershell_download_exec",
    "powershell_socket_listener",
    "powershell_socket_shell",
    "netcat_reverse_shell",
    "shell_reverse",
    "download_execute_chain",
    "decoded_eval_chain",
    "script_eval_exec_combo",
}
MACRO_AUTO_EXEC_MARKERS = {
    "autoopen",
    "document_open",
    "workbook_open",
    "presentation_open",
    "auto_open",
    "autoexec",
}
MACRO_DANGEROUS_MARKERS = {
    "wscript.shell",
    "shell(",
    ".run",
    "powershell",
    "cmd.exe",
    "regsvr32",
    "mshta",
    "rundll32",
    "urlmon",
    "urldownloadtofile",
    "xmlhttp",
    "winhttp",
    "downloadstring",
    "createobject(",
    "environ(",
}
EXECUTABLE_SIGNATURE_TYPES = {"pe_executable", "elf_executable", "macho_executable"}
DOCUMENT_BINARY_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".docm",
    ".xls",
    ".xlsx",
    ".xlsm",
    ".ppt",
    ".pptx",
    ".pptm",
}
ZIP_DOCUMENT_EXTENSIONS = {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"}
OLE_DOCUMENT_EXTENSIONS = {".doc", ".xls", ".ppt"}
MACRO_ENABLED_OOXML_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm", ".xlam", ".ppam"}
NON_MACRO_OOXML_EXTENSIONS = {".docx", ".xlsx", ".pptx", ".dotx", ".xltx", ".potx"}
MACRO_CAPABLE_LEGACY_EXTENSIONS = {".doc", ".xls", ".ppt"}
SUSPICIOUS_DOCUMENT_EXTENSIONS = {".rtf", ".slk", ".xll", ".hta", ".chm", ".lnk", ".iso", ".img", ".one"}
ARCHIVE_EXTENSIONS = {".zip"}
SCRIPT_DISGUISE_EXTENSIONS = DOCUMENT_BINARY_EXTENSIONS | ARCHIVE_EXTENSIONS
ARCHIVE_HIGH_RISK_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".ps1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".hta",
    ".bat",
    ".cmd",
    ".com",
    ".pif",
    ".jar",
    ".lnk",
    ".iso",
    ".img",
    ".chm",
}
ARCHIVE_SUSPICIOUS_COMPRESSION_RATIO = 100.0
DYNAMIC_REQUEST_DECISIONS = {
    "not_requested",
    "request_dynamic",
    "skip_unsupported",
    "skip_size_limit",
    "skip_low_risk",
    "skip_policy_exempt",
    "request_but_provider_unavailable",
}
DYNAMIC_PROVIDER_DISABLED_NAMES = {"none", "off", "disabled", "noop", ""}
DYNAMIC_PROVIDER_READINESS_STATES = {
    "disabled",
    "fake",
    "misconfigured",
    "live_validated",
    "live_not_validated",
}
DEFAULT_DYNAMIC_PROVIDER_VALIDATION_ARTIFACT = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "benchmarks"
    / "provider_validation"
    / "file_dynamic_provider_validation_latest.json"
)


@dataclass
class _FilePureVerdictBundle:
    analysis_id: str
    analysis_timestamp: datetime
    tenant_id: str
    filename: str
    filesize_kb: float
    type_validation_result: FileTypeValidationResult
    malware_scan_result: MalwareScanResult
    ml_scan_payload: Optional[MLScanResult]
    overall_assessment: FileAnalysisOverallAssessment
    structured_verdict: FileStructuredVerdict
    explanation: Optional[XAIExplanation]
    highlights: Optional[List[Dict[str, Any]]]
    errors_encountered: List[str]

class FileAnalysisService:
    _instance: Optional['FileAnalysisService'] = None
    _ml_model: Optional[Any] = None
    _yara_rules: Optional[Any] = None
    _alerts_service_instance: Optional[AlertsService] = None
    _incident_response_service_instance: Optional[IncidentResponseService] = None
    _dynamic_provider: Optional[BaseDynamicAnalysisProvider] = None
    _dynamic_enabled: bool = False
    _dynamic_poll_interval_seconds: float = 0.25
    _dynamic_max_wait_seconds: float = 1.0
    _dynamic_policy_profile: str = "baseline_v1"
    _dynamic_policy_risk_threshold: float = 0.65
    _dynamic_policy_max_file_size_mb: float = float(MAX_FILE_SIZE_MB)
    _dynamic_policy_high_risk_mimes: set[str] = set()
    _dynamic_policy_exempt_exts: set[str] = set()
    _dynamic_requested_provider_name: str = "none"
    _dynamic_provider_diagnostics: Dict[str, Any] = {}
    _initialized_flag: bool = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(FileAnalysisService, cls).__new__(cls)
        return cls._instance

    def __init__(self, ml_model_path: str = "", yara_rules_path: str = "", alerts_service: Optional[AlertsService] = None):
        if self._initialized_flag and ml_model_path:
            return
        if ml_model_path and yara_rules_path and alerts_service:
            self._initialize_service(ml_model_path, yara_rules_path, alerts_service)

    def _initialize_service(self, ml_model_path: str, yara_rules_path: str, alerts_service: AlertsService):
        logger.info("Initializing FileAnalysisService...")
        try:
            self._ml_model = joblib.load(ml_model_path)
            logger.info("âœ… File Analysis ML model loaded successfully.")
        except Exception as e:
            logger.critical(f"âŒ FATAL: Failed to load file analysis model: {e}", exc_info=True)
        try:
            self._yara_rules = yara.compile(filepath=yara_rules_path)
            logger.info("âœ… YARA rules compiled successfully.")
        except Exception as e:
            logger.critical(f"âŒ FATAL: Failed to compile YARA rules: {e}", exc_info=True)
        # Prefer multi-file compilation so newly added rule files are active without code changes.
        try:
            rules_path = Path(yara_rules_path)
            rules_dir = rules_path.parent if rules_path.suffix.lower() == ".yar" else rules_path
            file_map = {}
            if rules_dir.exists() and rules_dir.is_dir():
                for f in rules_dir.glob("*.yar"):
                    file_map[f.name] = str(f)
            if file_map:
                self._yara_rules = yara.compile(filepaths=file_map)
                setattr(self, "_yara_multi", True)
                logger.info(f"YARA multi-file compile active ({len(file_map)} files).")
        except Exception as e_multi:
            logger.warning(f"YARA multi-file compile failed; continuing with previous ruleset: {e_multi}")

        self._alerts_service_instance = alerts_service
        try:
            self._incident_response_service_instance = IncidentResponseService.get_instance()
        except Exception:
            self._incident_response_service_instance = IncidentResponseService(alerts_service=alerts_service)
        dynamic_provider_name = str(os.getenv("FILE_DYNAMIC_PROVIDER", "none") or "none").strip().lower() or "none"
        self._dynamic_requested_provider_name = dynamic_provider_name
        self._dynamic_provider = create_dynamic_analysis_provider(dynamic_provider_name)
        self._dynamic_enabled = os.getenv("FILE_DYNAMIC_ENABLE", "false").strip().lower() in {"1", "true", "yes", "y"}
        try:
            self._dynamic_poll_interval_seconds = max(
                0.05,
                float(os.getenv("FILE_DYNAMIC_POLL_INTERVAL_SECONDS", "0.25")),
            )
        except Exception:
            self._dynamic_poll_interval_seconds = 0.25
        try:
            self._dynamic_max_wait_seconds = max(
                0.0,
                float(os.getenv("FILE_DYNAMIC_MAX_WAIT_SECONDS", "1.0")),
            )
        except Exception:
            self._dynamic_max_wait_seconds = 1.0
        self._dynamic_policy_profile = str(os.getenv("FILE_DYNAMIC_POLICY_PROFILE", "baseline_v1") or "baseline_v1").strip() or "baseline_v1"
        try:
            self._dynamic_policy_risk_threshold = max(
                0.0,
                min(1.0, float(os.getenv("FILE_DYNAMIC_POLICY_RISK_THRESHOLD", "0.65"))),
            )
        except Exception:
            self._dynamic_policy_risk_threshold = 0.65
        try:
            self._dynamic_policy_max_file_size_mb = max(
                0.1,
                float(os.getenv("FILE_DYNAMIC_MAX_FILE_SIZE_MB", str(MAX_FILE_SIZE_MB))),
            )
        except Exception:
            self._dynamic_policy_max_file_size_mb = float(MAX_FILE_SIZE_MB)
        self._dynamic_policy_high_risk_mimes = set(
            m.strip().lower()
            for m in str(
                os.getenv(
                    "FILE_DYNAMIC_POLICY_HIGH_RISK_MIMES",
                    "application/pdf,application/zip,application/msword,application/vnd.ms-excel,application/vnd.ms-powerpoint,application/vnd.ms-word.document.macroEnabled.12,application/vnd.ms-excel.sheet.macroEnabled.12,application/vnd.ms-powerpoint.presentation.macroEnabled.12,application/octet-stream",
                )
            ).split(",")
            if m.strip()
        )
        self._dynamic_policy_exempt_exts = set(
            ext.strip().lower()
            for ext in str(os.getenv("FILE_DYNAMIC_POLICY_EXEMPT_EXTS", ".txt,.md,.csv")).split(",")
            if ext.strip()
        )
        self._refresh_dynamic_provider_diagnostics()
        self._initialized_flag = True

    @classmethod
    def get_instance(cls) -> 'FileAnalysisService':
        if cls._instance is None:
            raise RuntimeError("FileAnalysisService has not been initialized.")
        return cls._instance

    def are_resources_loaded(self) -> bool:
        return self._ml_model is not None and self._yara_rules is not None

    @staticmethod
    def _derive_dynamic_provider_readiness_state(
        *,
        enabled: bool,
        provider_name: str,
        configured: bool,
        validation_state: Optional[str],
    ) -> str:
        provider = str(provider_name or "").strip().lower()
        if not enabled or provider in DYNAMIC_PROVIDER_DISABLED_NAMES:
            return "disabled"
        if provider == "fake":
            return "fake"
        if not configured:
            return "misconfigured"
        if str(validation_state or "").strip().lower() == "live_validated":
            return "live_validated"
        return "live_not_validated"

    def _resolve_dynamic_validation_artifact_path(self) -> Path:
        env_path = str(os.getenv("FILE_DYNAMIC_VALIDATION_ARTIFACT", "") or "").strip()
        if env_path:
            return Path(env_path).resolve()
        return DEFAULT_DYNAMIC_PROVIDER_VALIDATION_ARTIFACT.resolve()

    def _load_dynamic_provider_validation_snapshot(
        self,
        *,
        provider_name: str,
        provider_details: Dict[str, Any],
    ) -> Dict[str, Any]:
        artifact_path = self._resolve_dynamic_validation_artifact_path()
        snapshot: Dict[str, Any] = {
            "exists": False,
            "artifact_path": str(artifact_path),
            "validation_state": "live_not_validated",
            "validated": False,
            "reason": "validation_artifact_missing",
            "checked_at": None,
            "provider": None,
            "provider_base_url": None,
            "provider_match": False,
            "base_url_match": True,
        }
        if not artifact_path.exists():
            return snapshot

        try:
            raw = json.loads(artifact_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                snapshot["reason"] = "validation_artifact_invalid_payload"
                return snapshot
        except Exception as exc:
            snapshot["reason"] = f"validation_artifact_read_error:{str(exc)[:120]}"
            return snapshot

        artifact_provider = str(raw.get("provider") or "").strip().lower()
        requested_provider = str(provider_name or "").strip().lower()
        provider_match = bool(artifact_provider and artifact_provider == requested_provider)

        artifact_state = str(raw.get("validation_state") or "").strip().lower() or "live_not_validated"
        if artifact_state not in DYNAMIC_PROVIDER_READINESS_STATES:
            artifact_state = "live_not_validated"
        artifact_validated = bool(raw.get("validated"))
        artifact_reason = str(raw.get("reason") or "").strip() or None
        artifact_checked_at = str(raw.get("checked_at") or "").strip() or None
        artifact_base_url = str(raw.get("provider_base_url") or "").strip() or None
        expected_base_url = str(provider_details.get("base_url") or "").strip() or None
        base_url_match = (
            True
            if not expected_base_url or not artifact_base_url
            else artifact_base_url.rstrip("/").lower() == expected_base_url.rstrip("/").lower()
        )

        normalized_state = artifact_state if provider_match and base_url_match else "live_not_validated"
        normalized_validated = bool(artifact_validated and normalized_state == "live_validated")
        normalized_reason = artifact_reason
        if not provider_match:
            normalized_reason = "validation_provider_mismatch"
        elif not base_url_match:
            normalized_reason = "validation_base_url_mismatch"
        elif not normalized_validated:
            normalized_reason = normalized_reason or "live_not_validated"

        snapshot.update(
            {
                "exists": True,
                "validation_state": normalized_state,
                "validated": normalized_validated,
                "reason": normalized_reason,
                "checked_at": artifact_checked_at,
                "provider": artifact_provider or None,
                "provider_base_url": artifact_base_url,
                "provider_match": provider_match,
                "base_url_match": base_url_match,
            }
        )
        return snapshot

    def _refresh_dynamic_provider_diagnostics(self) -> Dict[str, Any]:
        provider = self._dynamic_provider or create_dynamic_analysis_provider("none")
        provider_name = str(getattr(provider, "name", "none") or "none").strip().lower() or "none"
        provider_diag: Dict[str, Any] = {}
        try:
            diag_fn = getattr(provider, "diagnostics", None)
            if callable(diag_fn):
                raw = diag_fn()
                if isinstance(raw, dict):
                    provider_diag = dict(raw)
        except Exception as exc:
            provider_diag = {"reason": f"diagnostics_error:{str(exc)[:120]}", "configured": False, "available": False}

        available = bool(provider_diag.get("available")) if "available" in provider_diag else provider_name not in DYNAMIC_PROVIDER_DISABLED_NAMES
        configured = bool(provider_diag.get("configured")) if "configured" in provider_diag else available
        reason = str(provider_diag.get("reason") or "").strip() or None
        details = provider_diag.get("details")
        if not isinstance(details, dict):
            details = {}
        validation = self._load_dynamic_provider_validation_snapshot(
            provider_name=provider_name,
            provider_details=details,
        )
        readiness_state = self._derive_dynamic_provider_readiness_state(
            enabled=bool(self._dynamic_enabled),
            provider_name=provider_name,
            configured=configured,
            validation_state=str(validation.get("validation_state") or "").strip().lower(),
        )

        status = {
            "enabled": bool(self._dynamic_enabled),
            "requested_provider": str(self._dynamic_requested_provider_name or provider_name),
            "active_provider": provider_name,
            "configured": configured,
            "available": available,
            "misconfigured": bool(not configured and provider_name not in DYNAMIC_PROVIDER_DISABLED_NAMES),
            "readiness_state": readiness_state,
            "reason": reason,
            "poll_interval_seconds": float(self._dynamic_poll_interval_seconds),
            "max_wait_seconds": float(self._dynamic_max_wait_seconds),
            "policy_profile": str(self._dynamic_policy_profile or "baseline_v1"),
            "details": details,
            "validation": validation,
        }
        self._dynamic_provider_diagnostics = status

        logger.info(
            "File dynamic provider status: enabled=%s requested=%s active=%s configured=%s available=%s readiness=%s reason=%s",
            status["enabled"],
            status["requested_provider"],
            status["active_provider"],
            status["configured"],
            status["available"],
            status["readiness_state"],
            status["reason"],
        )
        if status["enabled"] and status["readiness_state"] in {"misconfigured", "live_not_validated"}:
            logger.warning(
                "File dynamic readiness is not fully validated (provider=%s readiness=%s reason=%s validation_reason=%s).",
                status["active_provider"],
                status["readiness_state"],
                status["reason"] or "unknown",
                (status.get("validation") or {}).get("reason"),
            )
        return status

    def get_dynamic_provider_status(self) -> Dict[str, Any]:
        current_provider = str(getattr(self._dynamic_provider, "name", "none") or "none").strip().lower() or "none"
        if (
            not isinstance(self._dynamic_provider_diagnostics, dict)
            or not self._dynamic_provider_diagnostics
            or str(self._dynamic_provider_diagnostics.get("active_provider") or "").strip().lower() != current_provider
        ):
            return self._refresh_dynamic_provider_diagnostics()
        status = dict(self._dynamic_provider_diagnostics)
        # Keep runtime toggles fresh even if provider object did not change.
        status["enabled"] = bool(self._dynamic_enabled)
        status["poll_interval_seconds"] = float(self._dynamic_poll_interval_seconds)
        status["max_wait_seconds"] = float(self._dynamic_max_wait_seconds)
        status["policy_profile"] = str(self._dynamic_policy_profile or "baseline_v1")
        status["readiness_state"] = self._derive_dynamic_provider_readiness_state(
            enabled=bool(status.get("enabled")),
            provider_name=str(status.get("active_provider") or current_provider),
            configured=bool(status.get("configured")),
            validation_state=str(((status.get("validation") or {}).get("validation_state") or "")).strip().lower(),
        )
        return status

    def configure_dynamic_runtime(
        self,
        *,
        enabled: Optional[bool] = None,
        provider_name: Optional[str] = None,
        provider_config: Optional[Dict[str, Any]] = None,
        poll_interval_seconds: Optional[float] = None,
        max_wait_seconds: Optional[float] = None,
    ) -> Dict[str, Any]:
        if provider_name is not None:
            requested_name = str(provider_name or "none").strip().lower() or "none"
            self._dynamic_requested_provider_name = requested_name
            self._dynamic_provider = create_dynamic_analysis_provider(requested_name, provider_config)
        if enabled is not None:
            self._dynamic_enabled = bool(enabled)
        if poll_interval_seconds is not None:
            try:
                self._dynamic_poll_interval_seconds = max(0.05, float(poll_interval_seconds))
            except Exception:
                pass
        if max_wait_seconds is not None:
            try:
                self._dynamic_max_wait_seconds = max(0.0, float(max_wait_seconds))
            except Exception:
                pass
        return self._refresh_dynamic_provider_diagnostics()

    @staticmethod
    def _assessment_classification(overall_assessment: FileAnalysisOverallAssessment) -> str:
        status_lc = str(overall_assessment.overall_status or "").lower()
        action_uc = str(overall_assessment.recommended_action or "").upper()
        if (
            ("BLOCK" in action_uc)
            or ("QUARANTINE" in action_uc)
            or ("malicious" in status_lc)
            or ("blocked" in status_lc)
        ):
            return "blocked"
        if (
            ("suspicious" in status_lc)
            or ("FLAG" in action_uc)
            or ("WARN" in action_uc)
            or ("REVIEW" in action_uc)
        ):
            return "suspicious"
        return "safe"

    @staticmethod
    def _classification_severity(classification: str) -> str:
        if classification == "blocked":
            return "high"
        if classification == "suspicious":
            return "medium"
        return "low"

    @staticmethod
    def _risk_score_value(overall_assessment: FileAnalysisOverallAssessment) -> Optional[float]:
        try:
            risk = overall_assessment.risk_score
            if isinstance(risk, (int, float)):
                return round(max(0.0, min(1.0, float(risk))), 4)
        except Exception:
            return None
        return None

    @staticmethod
    def _clamp01(value: Any) -> float:
        try:
            return max(0.0, min(1.0, float(value)))
        except Exception:
            return 0.0

    @classmethod
    def _decision_confidence_from_file_risk(
        cls,
        *,
        risk_score: Any,
        recommended_action: str,
        overall_status: str = "",
        uncertainty_score: Any = 0.0,
        ood_score: Any = 0.0,
    ) -> float:
        risk = cls._clamp01(risk_score)
        action = str(recommended_action or "").strip().upper().replace("-", "_")
        status = str(overall_status or "").strip().lower()
        safe_decision = (
            action.startswith("ALLOW")
            or action in {"SAFE", "CLEAN", "ALLOW_UPLOAD"}
            or ("safe" in status and not any(token in action for token in {"BLOCK", "FLAG", "REVIEW", "QUARANTINE"}))
        )
        base_confidence = (1.0 - risk) if safe_decision else risk
        _ = uncertainty_score, ood_score
        return round(cls._clamp01(base_confidence), 4)

    @staticmethod
    def _confidence_label(value: Optional[float]) -> Optional[str]:
        if not isinstance(value, (int, float)):
            return None
        if value >= 0.85:
            return "high"
        if value >= 0.60:
            return "medium"
        return "low"

    @staticmethod
    def _normalize_ioc_value(ioc_type: str, value: Any) -> Optional[str]:
        text = str(value or "").strip()
        if not text:
            return None
        kind = str(ioc_type or "").strip().lower()
        if kind in {"domain", "email", "hash", "ip"}:
            return text.lower()
        if kind == "url":
            parsed = urlparse(text)
            if parsed.scheme and parsed.netloc:
                normalized_path = parsed.path or ""
                normalized_q = f"?{parsed.query}" if parsed.query else ""
                return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{normalized_path}{normalized_q}"
            return text.lower()
        if kind == "command":
            return re.sub(r"\s+", " ", text).strip()
        if kind == "path":
            return text.replace("\\\\", "\\")
        return text

    @staticmethod
    def _build_ioc_dedup_key(ioc_type: str, normalized_value: str) -> str:
        return f"{str(ioc_type).lower()}:{normalized_value.lower()}"

    @staticmethod
    def _stage_confidence(stage: str, *, default: float = 0.6) -> float:
        stage_lc = str(stage or "").strip().lower()
        if stage_lc in {"hashing", "archive_scan"}:
            return 0.95
        if stage_lc in {"signature_scan", "yara"}:
            return 0.9
        if stage_lc in {"heuristics", "content_scan"}:
            return 0.75
        if stage_lc in {"ml_scan"}:
            return 0.7
        return default

    def _extract_normalized_iocs(
        self,
        *,
        file_content: bytes,
        filename: str,
        overall_assessment: FileAnalysisOverallAssessment,
        malware_scan_details: Dict[str, Any],
        inner_yara_matches: List[Dict[str, Any]],
        archive_lineage: List[str],
        exec_markers: List[str],
    ) -> List[FileIOC]:
        candidates: List[FileIOC] = []

        def add_ioc(
            ioc_type: str,
            value: Any,
            *,
            source_stage: str,
            source_path: Optional[str] = None,
            archive_paths: Optional[List[str]] = None,
            confidence: Optional[float] = None,
            severity_hint: Optional[str] = None,
        ) -> None:
            normalized = self._normalize_ioc_value(ioc_type, value)
            if not normalized:
                return
            dedup_key = self._build_ioc_dedup_key(ioc_type, normalized)
            conf = confidence if isinstance(confidence, (int, float)) else self._stage_confidence(source_stage)
            ioc = FileIOC(
                type=str(ioc_type).lower(),
                value=normalized,
                source_stage=str(source_stage or "unknown"),
                source_path=str(source_path or "").strip() or None,
                archive_lineage=[str(p).strip() for p in (archive_paths or []) if str(p).strip()] or None,
                confidence=round(max(0.0, min(1.0, float(conf))), 4),
                severity_hint=str(severity_hint or "").strip().lower() or None,
                dedup_key=dedup_key,
                provenance=[
                    {
                        "source_stage": str(source_stage or "unknown"),
                        "source_path": str(source_path or "").strip() or None,
                    }
                ],
            )
            candidates.append(ioc)

        # Deterministic content hashes (outer file)
        try:
            add_ioc("hash", hashlib.sha256(file_content).hexdigest(), source_stage="hashing", confidence=0.99, severity_hint="medium")
            add_ioc("hash", hashlib.sha1(file_content).hexdigest(), source_stage="hashing", confidence=0.99, severity_hint="medium")
            add_ioc("hash", hashlib.md5(file_content).hexdigest(), source_stage="hashing", confidence=0.99, severity_hint="medium")
        except Exception:
            pass

        text_content = ""
        try:
            text_source = (file_content or b"")[:IOC_TEXT_SCAN_LIMIT_BYTES]
            text_content = text_source.decode("utf-8", errors="ignore")
        except Exception:
            text_content = ""

        if text_content:
            for raw_url in sorted(set(_URL_RE.findall(text_content))):
                add_ioc("url", raw_url, source_stage="content_scan", severity_hint="medium")
                try:
                    host = urlparse(raw_url).hostname
                    if host:
                        add_ioc("domain", host, source_stage="content_scan", severity_hint="medium")
                except Exception:
                    pass

            for raw_email in sorted(set(_EMAIL_RE.findall(text_content))):
                add_ioc("email", raw_email, source_stage="content_scan", severity_hint="medium")
                if "@" in raw_email:
                    add_ioc("domain", raw_email.split("@", 1)[1], source_stage="content_scan", severity_hint="medium")

            for raw_ip in sorted(set(_IPV4_RE.findall(text_content))):
                add_ioc("ip", raw_ip, source_stage="content_scan", severity_hint="medium")

            for raw_domain in sorted(set(_DOMAIN_RE.findall(text_content))):
                add_ioc("domain", raw_domain, source_stage="content_scan", severity_hint="low")

            for raw_hash in sorted(set(_HASH_RE.findall(text_content))):
                if len(raw_hash) in {32, 40, 56, 64, 96, 128}:
                    add_ioc("hash", raw_hash, source_stage="content_scan", severity_hint="medium")

            for raw_path in sorted(set(_WIN_PATH_RE.findall(text_content))):
                add_ioc("path", raw_path, source_stage="content_scan", severity_hint="medium")

            for raw_path in sorted(set(_UNIX_PATH_RE.findall(text_content))):
                add_ioc("path", raw_path, source_stage="content_scan", severity_hint="medium")

            for cmd_kind, pattern in _COMMAND_PATTERNS:
                for cmd_text in sorted(set(pattern.findall(text_content))):
                    severity = "high" if cmd_kind in {"powershell", "regsvr32", "netcat"} else "medium"
                    add_ioc("command", cmd_text, source_stage="heuristics", severity_hint=severity)

        # Existing static analysis outputs: keep provenance and nested-path context.
        web_skimmer = malware_scan_details.get("web_skimmer") if isinstance(malware_scan_details, dict) else None
        if isinstance(web_skimmer, dict):
            for d in (web_skimmer.get("domains") or []):
                add_ioc("domain", d, source_stage="heuristics", severity_hint="high")

        for marker in (exec_markers or []):
            add_ioc("command", marker, source_stage="heuristics", severity_hint="high")

        macro_payload = malware_scan_details.get("macro") if isinstance(malware_scan_details, dict) else None
        if isinstance(macro_payload, dict):
            for macro_path in (macro_payload.get("paths") or []):
                add_ioc(
                    "path",
                    macro_path,
                    source_stage="archive_scan",
                    source_path=str(macro_path),
                    archive_paths=[str(macro_path)],
                    severity_hint="medium",
                )

        for entry in (inner_yara_matches or []):
            if not isinstance(entry, dict):
                continue
            nested_path = str(entry.get("path") or "").strip()
            if nested_path:
                add_ioc(
                    "path",
                    nested_path,
                    source_stage="archive_scan",
                    source_path=nested_path,
                    archive_paths=[nested_path],
                    severity_hint="medium",
                )

        # Merge duplicates while preserving traceability.
        merged: Dict[str, FileIOC] = {}
        for item in candidates:
            existing = merged.get(item.dedup_key)
            if existing is None:
                merged[item.dedup_key] = item
                continue

            existing_conf = float(existing.confidence or 0.0)
            candidate_conf = float(item.confidence or 0.0)
            if candidate_conf > existing_conf:
                existing.confidence = candidate_conf

            priority = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            old_sev = str(existing.severity_hint or "").lower()
            new_sev = str(item.severity_hint or "").lower()
            if priority.get(new_sev, 0) > priority.get(old_sev, 0):
                existing.severity_hint = new_sev

            lineage = list(existing.archive_lineage or [])
            for path in (item.archive_lineage or []):
                if path not in lineage:
                    lineage.append(path)
            existing.archive_lineage = lineage or None

            provenance = list(existing.provenance or [])
            for prov in (item.provenance or []):
                if prov not in provenance:
                    provenance.append(prov)
            existing.provenance = provenance or None

            if not existing.source_path and item.source_path:
                existing.source_path = item.source_path

        # Stable deterministic order.
        ordered = sorted(
            merged.values(),
            key=lambda item: (
                str(item.type or ""),
                str(item.value or ""),
                str(item.source_stage or ""),
                str(item.source_path or ""),
            ),
        )

        # Classification-sensitive trim to avoid oversized payloads while keeping diversity.
        max_iocs = 128 if self._assessment_classification(overall_assessment) != "safe" else 64
        return ordered[:max_iocs]

    @staticmethod
    def _dedupe_iocs(items: List[FileIOC]) -> List[FileIOC]:
        merged: Dict[str, FileIOC] = {}
        for item in items:
            dedup_key = str(item.dedup_key or "").strip()
            if not dedup_key:
                continue
            existing = merged.get(dedup_key)
            if existing is None:
                merged[dedup_key] = item
                continue

            if float(item.confidence or 0.0) > float(existing.confidence or 0.0):
                existing.confidence = item.confidence

            priority = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            old_sev = str(existing.severity_hint or "").lower()
            new_sev = str(item.severity_hint or "").lower()
            if priority.get(new_sev, 0) > priority.get(old_sev, 0):
                existing.severity_hint = item.severity_hint

            lineage = list(existing.archive_lineage or [])
            for p in (item.archive_lineage or []):
                if p not in lineage:
                    lineage.append(p)
            existing.archive_lineage = lineage or None

            provenance = list(existing.provenance or [])
            for record in (item.provenance or []):
                if record not in provenance:
                    provenance.append(record)
            existing.provenance = provenance or None

            if not existing.source_path and item.source_path:
                existing.source_path = item.source_path
            if not existing.source_stage and item.source_stage:
                existing.source_stage = item.source_stage

        return sorted(
            merged.values(),
            key=lambda i: (
                str(i.type or ""),
                str(i.value or ""),
                str(i.source_stage or ""),
                str(i.source_path or ""),
            ),
        )

    @staticmethod
    def decide_dynamic_analysis_request(
        static_verdict: FileStructuredVerdict,
        file_profile: Dict[str, Any],
        provider_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Pure deterministic policy function for dynamic-analysis request decisions."""
        trace: List[Dict[str, Any]] = []
        reason_codes: List[str] = []
        requested = False
        decision = "not_requested"
        skip_reason: Optional[str] = None

        policy_profile = str(provider_context.get("policy_profile") or "baseline_v1").strip() or "baseline_v1"
        dynamic_enabled = bool(provider_context.get("dynamic_enabled"))
        provider_name = str(provider_context.get("provider_name") or "none").strip().lower() or "none"
        if "provider_available" in provider_context:
            provider_available = bool(provider_context.get("provider_available"))
        else:
            provider_available = provider_name not in {"none", "off", "disabled", "noop", ""}
        risk_threshold = float(provider_context.get("risk_threshold") if isinstance(provider_context.get("risk_threshold"), (int, float)) else 0.65)
        high_risk_mimes = set(str(v).strip().lower() for v in (provider_context.get("high_risk_mimes") or []))
        exempt_exts = set(str(v).strip().lower() for v in (provider_context.get("exempt_exts") or []))

        classification = str(static_verdict.classification or "").strip().lower() or "safe"
        detected_type = str(static_verdict.detected_type or "").strip().lower()
        declared_type = str(static_verdict.declared_type or "").strip().lower()
        score = float(static_verdict.score) if isinstance(static_verdict.score, (int, float)) else 0.0
        is_allowed_type = bool(file_profile.get("is_allowed_type", True))
        is_oversize = bool(file_profile.get("is_oversize", False))
        has_signature_hit = bool(file_profile.get("has_signature_hit", False))
        has_macro = bool(file_profile.get("has_macro", False))
        has_archive_findings = bool(file_profile.get("has_archive_findings", False))
        has_exec_markers = bool(file_profile.get("has_exec_markers", False))
        has_pdf_active = bool(file_profile.get("has_pdf_active", False))

        trace.append({"step": "dynamic_enabled", "value": dynamic_enabled, "provider": provider_name, "provider_available": provider_available})
        if not dynamic_enabled:
            reason_codes.append("dynamic_disabled")
            return {
                "requested": False,
                "request_decision": "not_requested",
                "reason_codes": reason_codes,
                "policy_profile": policy_profile,
                "request_trace": trace,
                "skip_reason": "dynamic_disabled",
            }

        if is_oversize:
            reason_codes.append("oversize_file")
            skip_reason = "skip_size_limit"
            trace.append({"step": "size_check", "status": "skip", "size_kb": file_profile.get("filesize_kb"), "max_size_mb": file_profile.get("max_dynamic_size_mb")})
            return {
                "requested": False,
                "request_decision": "skip_size_limit",
                "reason_codes": reason_codes,
                "policy_profile": policy_profile,
                "request_trace": trace,
                "skip_reason": skip_reason,
            }

        if not is_allowed_type:
            reason_codes.append("unsupported_file_type")
            skip_reason = "skip_unsupported"
            trace.append({"step": "type_support_check", "status": "skip", "detected_type": detected_type})
            return {
                "requested": False,
                "request_decision": "skip_unsupported",
                "reason_codes": reason_codes,
                "policy_profile": policy_profile,
                "request_trace": trace,
                "skip_reason": skip_reason,
            }

        if declared_type and declared_type in exempt_exts and classification == "safe" and not has_signature_hit:
            reason_codes.append("policy_exempt_extension")
            skip_reason = "skip_policy_exempt"
            trace.append({"step": "policy_exempt_check", "status": "skip", "declared_type": declared_type})
            return {
                "requested": False,
                "request_decision": "skip_policy_exempt",
                "reason_codes": reason_codes,
                "policy_profile": policy_profile,
                "request_trace": trace,
                "skip_reason": skip_reason,
            }

        dynamic_triggers: List[str] = []
        if classification == "blocked":
            dynamic_triggers.append("blocked_static_verdict")
        if classification == "suspicious" and score >= risk_threshold:
            dynamic_triggers.append("suspicious_over_threshold")
        if detected_type and detected_type in high_risk_mimes:
            dynamic_triggers.append("high_risk_mime")
        if has_signature_hit:
            dynamic_triggers.append("signature_hit")
        if has_macro:
            dynamic_triggers.append("macro_indicator")
        if has_archive_findings:
            dynamic_triggers.append("archive_nested_findings")
        if has_exec_markers:
            dynamic_triggers.append("execution_markers")
        if has_pdf_active:
            dynamic_triggers.append("pdf_active_content")

        trace.append(
            {
                "step": "trigger_evaluation",
                "classification": classification,
                "score": round(score, 4),
                "risk_threshold": risk_threshold,
                "detected_type": detected_type,
                "triggers": list(dynamic_triggers),
            }
        )

        if not dynamic_triggers:
            reason_codes.append("low_risk_static_verdict")
            skip_reason = "skip_low_risk"
            return {
                "requested": False,
                "request_decision": "skip_low_risk",
                "reason_codes": reason_codes,
                "policy_profile": policy_profile,
                "request_trace": trace,
                "skip_reason": skip_reason,
            }

        reason_codes.extend(dynamic_triggers)
        if not provider_available:
            trace.append({"step": "provider_availability", "status": "unavailable", "provider": provider_name})
            return {
                "requested": False,
                "request_decision": "request_but_provider_unavailable",
                "reason_codes": reason_codes + ["provider_unavailable"],
                "policy_profile": policy_profile,
                "request_trace": trace,
                "skip_reason": "provider_unavailable",
            }

        requested = True
        decision = "request_dynamic"
        trace.append({"step": "provider_availability", "status": "available", "provider": provider_name})
        return {
            "requested": requested,
            "request_decision": decision,
            "reason_codes": reason_codes,
            "policy_profile": policy_profile,
            "request_trace": trace,
            "skip_reason": None,
        }

    @staticmethod
    def _apply_dynamic_policy_metadata(
        state: FileDynamicAnalysisState,
        decision: Dict[str, Any],
    ) -> FileDynamicAnalysisState:
        state.requested = bool(decision.get("requested", False))
        request_decision = str(decision.get("request_decision") or "not_requested").strip().lower() or "not_requested"
        if request_decision not in DYNAMIC_REQUEST_DECISIONS:
            request_decision = "not_requested"
        state.request_decision = request_decision
        state.reason_codes = [str(code).strip() for code in (decision.get("reason_codes") or []) if str(code).strip()]
        state.policy_profile = str(decision.get("policy_profile") or "").strip() or None
        state.request_trace = list(decision.get("request_trace") or [])
        state.skip_reason = str(decision.get("skip_reason") or "").strip() or None
        return state

    @staticmethod
    def _dynamic_state_from_policy_decision(
        *,
        provider_name: str,
        decision: Dict[str, Any],
    ) -> FileDynamicAnalysisState:
        request_decision = str(decision.get("request_decision") or "not_requested").strip().lower() or "not_requested"
        if request_decision == "request_but_provider_unavailable":
            state = FileDynamicAnalysisState(
                provider=provider_name,
                submission_id=None,
                dynamic_status="unavailable",
                submitted_at=None,
                completed_at=None,
                failure_reason="provider_unavailable",
                dynamic_summary="Dynamic analysis requested by policy but provider is unavailable.",
                dynamic_evidence_items=[],
                dynamic_iocs=[],
            )
            return FileAnalysisService._apply_dynamic_policy_metadata(state, decision)

        if request_decision == "request_dynamic" and bool(decision.get("requested")):
            state = FileDynamicAnalysisState(
                provider=provider_name,
                submission_id=None,
                dynamic_status="pending_submission",
                submitted_at=None,
                completed_at=None,
                failure_reason=None,
                dynamic_summary="Dynamic analysis requested by policy.",
                dynamic_evidence_items=[],
                dynamic_iocs=[],
            )
            return FileAnalysisService._apply_dynamic_policy_metadata(state, decision)

        state = FileDynamicAnalysisState(
            provider=provider_name,
            submission_id=None,
            dynamic_status="not_requested",
            submitted_at=None,
            completed_at=None,
            failure_reason=None,
            dynamic_summary="Dynamic analysis not requested by policy.",
            dynamic_evidence_items=[],
            dynamic_iocs=[],
        )
        return FileAnalysisService._apply_dynamic_policy_metadata(state, decision)

    def _normalize_dynamic_result(
        self,
        *,
        provider_name: str,
        result: DynamicResultPayload,
        default_submission_id: Optional[str],
    ) -> FileDynamicAnalysisState:
        status = str(getattr(result, "status", "") or "").strip().lower() or "failed"
        if status not in {"submitted", "running", "completed", "failed", "unavailable"}:
            status = "failed"

        dynamic_evidence: List[FileVerdictEvidenceItem] = []
        for evidence in list(getattr(result, "evidence_items", []) or []):
            if isinstance(evidence, DynamicEvidenceItem):
                dynamic_evidence.append(
                    FileVerdictEvidenceItem(
                        code=str(evidence.code or "dynamic_evidence").strip() or "dynamic_evidence",
                        label=str(evidence.label or "Dynamic analysis evidence").strip() or "Dynamic analysis evidence",
                        severity=str(evidence.severity or "").strip().lower() or None,
                        source=f"dynamic:{provider_name}",
                        path=str(evidence.source_path or "").strip() or None,
                        details=dict(evidence.details or {}),
                    )
                )
            elif isinstance(evidence, dict):
                dynamic_evidence.append(
                    FileVerdictEvidenceItem(
                        code=str(evidence.get("code") or "dynamic_evidence").strip() or "dynamic_evidence",
                        label=str(evidence.get("label") or "Dynamic analysis evidence").strip() or "Dynamic analysis evidence",
                        severity=str(evidence.get("severity") or "").strip().lower() or None,
                        source=f"dynamic:{provider_name}",
                        path=str(evidence.get("source_path") or "").strip() or None,
                        details=dict(evidence.get("details") or {}),
                    )
                )

        dynamic_iocs: List[FileIOC] = []
        for ioc in list(getattr(result, "iocs", []) or []):
            if isinstance(ioc, DynamicIOCItem):
                ioc_type = str(ioc.ioc_type or "").strip().lower()
                ioc_value = self._normalize_ioc_value(ioc_type, ioc.value)
                if not ioc_type or not ioc_value:
                    continue
                dedup_key = self._build_ioc_dedup_key(ioc_type, ioc_value)
                dynamic_iocs.append(
                    FileIOC(
                        type=ioc_type,
                        value=ioc_value,
                        source_stage=f"dynamic:{provider_name}",
                        source_path=str(ioc.source_path or "").strip() or None,
                        archive_lineage=None,
                        confidence=round(max(0.0, min(1.0, float(ioc.confidence if isinstance(ioc.confidence, (int, float)) else 0.7))), 4),
                        severity_hint=str(ioc.severity_hint or "").strip().lower() or None,
                        dedup_key=dedup_key,
                        provenance=[
                            {
                                "source_stage": f"dynamic:{provider_name}",
                                "source_path": str(ioc.source_path or "").strip() or None,
                                "origin": "dynamic_provider",
                            }
                        ],
                    )
                )
            elif isinstance(ioc, dict):
                ioc_type = str(ioc.get("type") or ioc.get("ioc_type") or "").strip().lower()
                ioc_value = self._normalize_ioc_value(ioc_type, ioc.get("value"))
                if not ioc_type or not ioc_value:
                    continue
                dedup_key = self._build_ioc_dedup_key(ioc_type, ioc_value)
                conf = ioc.get("confidence")
                dynamic_iocs.append(
                    FileIOC(
                        type=ioc_type,
                        value=ioc_value,
                        source_stage=f"dynamic:{provider_name}",
                        source_path=str(ioc.get("source_path") or "").strip() or None,
                        archive_lineage=list(ioc.get("archive_lineage") or []) or None,
                        confidence=round(max(0.0, min(1.0, float(conf if isinstance(conf, (int, float)) else 0.7))), 4),
                        severity_hint=str(ioc.get("severity_hint") or "").strip().lower() or None,
                        dedup_key=dedup_key,
                        provenance=[
                            {
                                "source_stage": f"dynamic:{provider_name}",
                                "source_path": str(ioc.get("source_path") or "").strip() or None,
                                "origin": "dynamic_provider",
                            }
                        ],
                    )
                )

        return FileDynamicAnalysisState(
            provider=provider_name,
            submission_id=str(getattr(result, "submission_id", "") or default_submission_id or "").strip() or None,
            dynamic_status=status,
            submitted_at=None,
            completed_at=getattr(result, "completed_at", None),
            failure_reason=str(getattr(result, "failure_reason", "") or "").strip() or None,
            dynamic_summary=str(getattr(result, "summary", "") or "").strip() or None,
            dynamic_evidence_items=dynamic_evidence,
            dynamic_iocs=self._dedupe_iocs(dynamic_iocs),
        )

    async def _run_dynamic_analysis_stage(
        self,
        *,
        analysis_id: str,
        filename: str,
        file_content: bytes,
        detected_mime: str,
        overall_assessment: FileAnalysisOverallAssessment,
    ) -> FileDynamicAnalysisState:
        provider = self._dynamic_provider or create_dynamic_analysis_provider("none")
        provider_name = str(getattr(provider, "name", "none") or "none")
        state = FileDynamicAnalysisState(
            provider=provider_name,
            submission_id=None,
            dynamic_status="pending_submission",
            submitted_at=None,
            completed_at=None,
            failure_reason=None,
            dynamic_summary="Preparing external dynamic-analysis submission.",
            dynamic_evidence_items=[],
            dynamic_iocs=[],
        )

        try:
            handle = await provider.submit(
                sample_ref=analysis_id,
                sample_bytes=file_content,
                metadata={
                    "filename": filename,
                    "detected_mime": detected_mime,
                    "recommended_action": overall_assessment.recommended_action,
                    "overall_status": overall_assessment.overall_status,
                    "risk_score": overall_assessment.risk_score,
                },
            )
        except Exception as exc:
            state.dynamic_status = "unavailable"
            state.failure_reason = f"provider_submit_error:{str(exc)[:180]}"
            state.dynamic_summary = "Dynamic provider unavailable during submission."
            return state

        state.provider = str(getattr(handle, "provider", provider_name) or provider_name)
        state.submission_id = str(getattr(handle, "submission_id", "") or "").strip() or None
        state.submitted_at = getattr(handle, "submitted_at", None) or datetime.now(timezone.utc)
        submitted_status = str(getattr(handle, "status", "") or "").strip().lower()
        if submitted_status in {"unavailable", "failed"}:
            state.dynamic_status = submitted_status
            state.failure_reason = str(getattr(handle, "message", "") or "").strip() or f"provider_{submitted_status}"
            state.dynamic_summary = "Dynamic analysis unavailable from provider."
            return state
        state.dynamic_status = "submitted"
        state.dynamic_summary = "Dynamic analysis submitted to external provider."

        if not state.submission_id:
            state.dynamic_status = "failed"
            state.failure_reason = "missing_submission_id"
            state.dynamic_summary = "Provider did not return a submission identifier."
            return state

        if self._dynamic_max_wait_seconds <= 0:
            return state

        deadline = asyncio.get_event_loop().time() + float(self._dynamic_max_wait_seconds)
        current_status = "submitted"
        while asyncio.get_event_loop().time() <= deadline:
            try:
                snap = await provider.get_status(state.submission_id)
            except Exception as exc:
                state.dynamic_status = "failed"
                state.failure_reason = f"provider_status_error:{str(exc)[:180]}"
                state.dynamic_summary = "Failed to fetch dynamic-analysis status."
                return state

            current_status = str(getattr(snap, "status", "") or "").strip().lower() or current_status
            if current_status in {"submitted", "running"}:
                state.dynamic_status = current_status
                await asyncio.sleep(self._dynamic_poll_interval_seconds)
                continue
            if current_status in {"failed", "unavailable"}:
                state.dynamic_status = current_status
                state.failure_reason = str(getattr(snap, "failure_reason", "") or "").strip() or None
                state.dynamic_summary = "Dynamic analysis did not complete successfully."
                return state
            if current_status == "completed":
                try:
                    result = await provider.fetch_result(state.submission_id)
                except Exception as exc:
                    state.dynamic_status = "failed"
                    state.failure_reason = f"provider_result_error:{str(exc)[:180]}"
                    state.dynamic_summary = "Failed to retrieve dynamic-analysis result."
                    return state
                normalized = self._normalize_dynamic_result(
                    provider_name=state.provider or provider_name,
                    result=result,
                    default_submission_id=state.submission_id,
                )
                normalized.submitted_at = state.submitted_at
                return normalized
            state.dynamic_status = "failed"
            state.failure_reason = f"invalid_provider_status:{current_status}"
            state.dynamic_summary = "Dynamic provider returned an invalid status."
            return state

        state.dynamic_status = "running"
        state.dynamic_summary = "Dynamic analysis still running; provider result not ready in current scan window."
        return state

    def _build_structured_verdict(
        self,
        *,
        analysis_id: str,
        filename: str,
        file_content: bytes,
        type_validation_result: FileTypeValidationResult,
        malware_scan_result: MalwareScanResult,
        ml_scan_payload: Optional[MLScanResult],
        overall_assessment: FileAnalysisOverallAssessment,
        dangerous_yara_rules: List[str],
        suspicious_yara_rules: List[str],
        poc_yara_rules: List[str],
        inner_yara_matches: List[Dict[str, Any]],
        macro_present: bool,
        pdf_suspicious: bool,
        pdf_hits: List[str],
        exec_markers: List[str],
        ext_mismatch: bool,
        mismatch_reason: Optional[str],
        malware_scan_details: Dict[str, Any],
        macro_defense: Optional[MacroDefenseResult] = None,
    ) -> FileStructuredVerdict:
        classification = self._assessment_classification(overall_assessment)
        severity = self._classification_severity(classification)
        score = self._risk_score_value(overall_assessment)
        confidence = (
            self._decision_confidence_from_file_risk(
                risk_score=score,
                recommended_action=overall_assessment.recommended_action,
                overall_status=overall_assessment.overall_status,
            )
            if isinstance(score, (int, float))
            else None
        )

        declared_type = None
        try:
            _, ext = os.path.splitext(filename or "")
            declared_type = ext.lower() or None
        except Exception:
            declared_type = None

        matched_rules: List[str] = []
        matched_signatures: List[str] = []
        archive_lineage: List[str] = []
        evidence_items: List[FileVerdictEvidenceItem] = []
        analysis_stages: List[FileVerdictStage] = []

        def _append_rule(rule: Optional[str]) -> None:
            val = str(rule or "").strip()
            if val and val not in matched_rules:
                matched_rules.append(val)

        def _append_lineage(path: Optional[str]) -> None:
            val = str(path or "").strip()
            if val and val not in archive_lineage:
                archive_lineage.append(val)

        for rule in dangerous_yara_rules:
            _append_rule(rule)
        for rule in suspicious_yara_rules:
            _append_rule(rule)
        for rule in poc_yara_rules:
            _append_rule(rule)

        for inner_match in (inner_yara_matches or []):
            if not isinstance(inner_match, dict):
                continue
            _append_lineage(str(inner_match.get("path") or ""))
            rules = inner_match.get("rules") or []
            if isinstance(rules, list):
                for rule in rules:
                    _append_rule(str(rule))

        threat_name = str(malware_scan_result.threat_name or "").strip()
        if threat_name:
            matched_signatures.append(threat_name)

        clam_details = malware_scan_details.get("clamav") if isinstance(malware_scan_details, dict) else None
        if isinstance(clam_details, dict):
            signature = str(clam_details.get("signature") or "").strip()
            if signature and signature not in matched_signatures:
                matched_signatures.append(signature)
        macro_details = malware_scan_details.get("macro") if isinstance(malware_scan_details, dict) else None
        macro_risky = bool(isinstance(macro_details, dict) and macro_details.get("risky"))
        macro_defense_payload = macro_defense.model_dump() if macro_defense is not None else None
        archive_details = malware_scan_details.get("archive") if isinstance(malware_scan_details, dict) else None
        archive_suspicious = bool(isinstance(archive_details, dict) and archive_details.get("suspicious"))
        file_signature_details = malware_scan_details.get("file_signature") if isinstance(malware_scan_details, dict) else None
        signature_mismatch_details = None
        if isinstance(file_signature_details, dict):
            signature_mismatch_details = file_signature_details.get("extension_mismatch")

        if type_validation_result.is_allowed_type is False:
            evidence_items.append(
                FileVerdictEvidenceItem(
                    code="disallowed_type",
                    label="Disallowed file type",
                    severity="high",
                    source="type_validation",
                    details={"detected_type": type_validation_result.detected_mime_type},
                )
            )

        if matched_rules:
            evidence_items.append(
                FileVerdictEvidenceItem(
                    code="rule_match",
                    label="Signature/rule matches found",
                    severity="high" if classification == "blocked" else "medium",
                    source="yara",
                    details={"rules": matched_rules[:15]},
                )
            )

        if archive_lineage:
            evidence_items.append(
                FileVerdictEvidenceItem(
                    code="archive_nested_findings",
                    label="Nested archive/document findings",
                    severity="medium",
                    source="archive",
                    details={"paths": archive_lineage[:15]},
                )
            )

        if macro_present:
            evidence_items.append(
                FileVerdictEvidenceItem(
                    code="macro_defense",
                    label=(
                        "Critical macro behaviour detected"
                        if macro_defense and macro_defense.macro_risk_level == "critical"
                        else "Risky macro detected"
                        if macro_defense and macro_defense.macro_risk_level == "high"
                        else "Macro container present"
                    ),
                    severity=(
                        "critical"
                        if macro_defense and macro_defense.macro_risk_level == "critical"
                        else "high"
                        if macro_defense and macro_defense.macro_risk_level == "high"
                        else "medium"
                        if macro_defense and macro_defense.macro_risk_level == "medium"
                        else "low"
                    ),
                    source="macro_defense",
                    details=macro_defense_payload or (macro_details if isinstance(macro_details, dict) else None),
                )
            )
        elif macro_defense and macro_defense.macro_risk_score > 0:
            evidence_items.append(
                FileVerdictEvidenceItem(
                    code="macro_defense_finding",
                    label="Macro/Office package defence finding",
                    severity="medium",
                    source="macro_defense",
                    details=macro_defense_payload,
                )
            )

        if archive_suspicious:
            evidence_items.append(
                FileVerdictEvidenceItem(
                    code="archive_policy_indicator",
                    label="Archive policy indicators",
                    severity="medium",
                    source="archive",
                    details={
                        "reasons": list((archive_details or {}).get("suspicious_reasons") or [])[:10],
                        "entries": list((archive_details or {}).get("suspicious_entries") or [])[:15],
                    },
                )
            )

        if pdf_suspicious or pdf_hits:
            evidence_items.append(
                FileVerdictEvidenceItem(
                    code="pdf_active_content",
                    label="PDF active-content indicators",
                    severity="medium",
                    source="pdfid",
                    details={"keywords": list(pdf_hits or [])[:10]},
                )
            )

        if exec_markers:
            evidence_items.append(
                FileVerdictEvidenceItem(
                    code="exec_marker",
                    label="Execution markers detected",
                    severity="high" if any(m in {"powershell_socket_shell", "netcat_reverse_shell"} for m in exec_markers) else "medium",
                    source="heuristics",
                    details={"markers": list(exec_markers)[:12]},
                )
            )

        if ext_mismatch:
            evidence_items.append(
                FileVerdictEvidenceItem(
                    code="extension_content_mismatch",
                    label="Extension/content mismatch",
                    severity=str((signature_mismatch_details or {}).get("severity") or "medium") if isinstance(signature_mismatch_details, dict) else "medium",
                    source="type_validation",
                    details={
                        "reason": mismatch_reason,
                        "signature_mismatch": signature_mismatch_details if isinstance(signature_mismatch_details, dict) else None,
                    },
                )
            )

        if ml_scan_payload and bool(ml_scan_payload.is_suspicious_ml):
            evidence_items.append(
                FileVerdictEvidenceItem(
                    code="ml_suspicious",
                    label="ML model flagged suspicious content",
                    severity="medium",
                    source="ml",
                    details={
                        "label": ml_scan_payload.prediction_label_ml,
                        "score": ml_scan_payload.prediction_score_ml,
                    },
                )
            )

        analysis_stages.append(
            FileVerdictStage(
                stage="type_validation",
                status="ok" if type_validation_result.is_allowed_type else "hit",
                summary=f"detected={type_validation_result.detected_mime_type} allowed={type_validation_result.is_allowed_type}",
                details=type_validation_result.model_dump() if hasattr(type_validation_result, "model_dump") else None,
            )
        )
        analysis_stages.append(
            FileVerdictStage(
                stage="signature_scan",
                status="hit" if (matched_rules or matched_signatures) else "ok",
                summary=f"rules={len(matched_rules)} signatures={len(matched_signatures)}",
                details={"matched_rules": matched_rules[:20], "matched_signatures": matched_signatures[:10]},
            )
        )
        archive_status = "hit" if (archive_lineage or macro_risky or archive_suspicious) else "ok"
        analysis_stages.append(
            FileVerdictStage(
                stage="archive_scan",
                status=archive_status,
                summary=f"lineage={len(archive_lineage)} macro={bool(macro_present)} risky_macro={bool(macro_risky)} archive_suspicious={bool(archive_suspicious)}",
                details={
                    "archive_lineage": archive_lineage[:20],
                    "macro_present": bool(macro_present),
                    "macro_risky": bool(macro_risky),
                    "archive": archive_details if isinstance(archive_details, dict) else None,
                },
            )
        )
        if macro_defense is not None:
            macro_stage_status = "hit" if macro_defense.macro_risk_level in {"medium", "high", "critical"} else ("ok" if macro_defense.macro_present else "skipped")
            analysis_stages.append(
                FileVerdictStage(
                    stage="macro_defense",
                    status=macro_stage_status,
                    summary=(
                        f"present={macro_defense.macro_present} "
                        f"level={macro_defense.macro_risk_level} "
                        f"handling={macro_defense.recommended_handling}"
                    ),
                    details=macro_defense_payload,
                )
            )
        heur_status = "hit" if (exec_markers or ext_mismatch or pdf_suspicious or archive_suspicious or macro_risky) else "ok"
        analysis_stages.append(
            FileVerdictStage(
                stage="heuristics",
                status=heur_status,
                summary=f"exec_markers={len(exec_markers)} ext_mismatch={bool(ext_mismatch)} pdf_suspicious={bool(pdf_suspicious)} archive_suspicious={bool(archive_suspicious)}",
                details={
                    "exec_markers": list(exec_markers)[:10],
                    "ext_mismatch": bool(ext_mismatch),
                    "signature_mismatch": signature_mismatch_details if isinstance(signature_mismatch_details, dict) else None,
                    "archive_suspicious": bool(archive_suspicious),
                    "pdf_hits": list(pdf_hits or [])[:10],
                },
            )
        )
        if ml_scan_payload is None:
            analysis_stages.append(
                FileVerdictStage(
                    stage="ml_scan",
                    status="skipped",
                    summary="ML scan not applicable or unavailable.",
                )
            )
        else:
            analysis_stages.append(
                FileVerdictStage(
                    stage="ml_scan",
                    status="hit" if bool(ml_scan_payload.is_suspicious_ml) else "ok",
                    summary=f"label={ml_scan_payload.prediction_label_ml} score={ml_scan_payload.prediction_score_ml}",
                    details=ml_scan_payload.model_dump() if hasattr(ml_scan_payload, "model_dump") else None,
                )
            )
        analysis_stages.append(
            FileVerdictStage(
                stage="risk_assessment",
                status="hit" if classification != "safe" else "ok",
                summary=f"{overall_assessment.overall_status} -> {overall_assessment.recommended_action}",
                details=overall_assessment.model_dump() if hasattr(overall_assessment, "model_dump") else None,
            )
        )

        reasoning = list(overall_assessment.reasoning or [])
        if reasoning:
            analyst_summary = f"{overall_assessment.overall_status}: {'; '.join(reasoning[:3])}"
        else:
            analyst_summary = f"{overall_assessment.overall_status}: {overall_assessment.recommended_action}"

        normalized_iocs = self._extract_normalized_iocs(
            file_content=file_content,
            filename=filename,
            overall_assessment=overall_assessment,
            malware_scan_details=malware_scan_details,
            inner_yara_matches=inner_yara_matches,
            archive_lineage=archive_lineage,
            exec_markers=exec_markers,
        )
        if normalized_iocs:
            evidence_items.append(
                FileVerdictEvidenceItem(
                    code="normalized_ioc_count",
                    label="Normalized IOC extraction",
                    severity="medium" if classification != "safe" else "low",
                    source="ioc_normalization",
                    details={"count": len(normalized_iocs)},
                )
            )

        return FileStructuredVerdict(
            analysis_id=analysis_id,
            sample_id=filename,
            classification=classification,
            severity=severity,
            score=score,
            confidence=confidence,
            declared_type=declared_type,
            detected_type=type_validation_result.detected_mime_type,
            matched_rules=matched_rules,
            matched_signatures=matched_signatures,
            iocs=normalized_iocs,
            evidence_items=evidence_items,
            archive_lineage=archive_lineage,
            macro_defense=macro_defense,
            analysis_stages=analysis_stages,
            analyst_summary=analyst_summary,
        )

    def _persist_emit_alerts_from_verdict(
        self,
        *,
        db: Session,
        bundle: _FilePureVerdictBundle,
    ) -> Tuple[Optional[List[str]], Optional[Dict[str, Any]]]:
        status_lc = str(bundle.overall_assessment.overall_status or "").lower()
        action_uc = str(bundle.overall_assessment.recommended_action or "").upper()
        classification = str(bundle.structured_verdict.classification or "safe").lower()
        should_alert = classification in {"blocked", "suspicious"} or action_uc.startswith("BLOCK") or action_uc.startswith("FLAG")

        # Persist analysis log (existing schema preserved; structured verdict is embedded in JSON details).
        try:
            category = classification if classification in {"safe", "suspicious", "blocked"} else "safe"
            model = FileAnalysisLogModel(
                id=bundle.analysis_id,
                tenant_id=bundle.tenant_id,
                timestamp=bundle.analysis_timestamp,
                filename=bundle.filename,
                filesize_kb=round(bundle.filesize_kb, 2),
                overall_status=str(bundle.overall_assessment.overall_status or ""),
                recommended_action=str(bundle.overall_assessment.recommended_action or ""),
                risk_score_value=float(bundle.overall_assessment.risk_score) if isinstance(bundle.overall_assessment.risk_score, (int, float)) else None,
                category=category,
            )
            details_payload = {
                "type_validation": bundle.type_validation_result.model_dump() if hasattr(bundle.type_validation_result, "model_dump") else None,
                "malware_scan": bundle.malware_scan_result.model_dump() if hasattr(bundle.malware_scan_result, "model_dump") else None,
                "ml_scan": bundle.ml_scan_payload.model_dump() if (bundle.ml_scan_payload and hasattr(bundle.ml_scan_payload, "model_dump")) else None,
                "structured_verdict": bundle.structured_verdict.model_dump(mode="json"),
            }
            model.file_details = details_payload
            model.overall_assessment = bundle.overall_assessment.model_dump() if hasattr(bundle.overall_assessment, "model_dump") else None
            model.errors = bundle.errors_encountered or None
            db.add(model)
            db.commit()
        except Exception as e_persist:
            logger.error(f"Failed to persist file analysis log: {e_persist}", exc_info=True)
            try:
                db.rollback()
            except Exception:
                pass

        if should_alert and self._alerts_service_instance:
            severity = "High" if classification == "blocked" else "Medium"
            logger.info(f"File flagged ({bundle.overall_assessment.overall_status}); creating {severity} alert.")
            alert_to_create = AlertSchema(
                id=f"alert-{bundle.analysis_id}",
                timestamp=bundle.analysis_timestamp,
                severity=severity,
                title=f"File Alert: {bundle.overall_assessment.overall_status}",
                message=f"File '{bundle.filename}' was flagged. Reason: {', '.join(bundle.overall_assessment.reasoning or [])}",
                target="File_Analyzer",
                acknowledged=False,
            )
            created_alert_model = None
            try:
                created_alert_model = self._alerts_service_instance.create_alert(
                    db=db,
                    alert_data=alert_to_create,
                    tenant_id=bundle.tenant_id,
                )
            except Exception as e_alert:
                logger.error(f"Failed to persist file alert: {e_alert}", exc_info=True)
                try:
                    db.rollback()
                except Exception:
                    pass

            if created_alert_model is not None:
                try:
                    alert_details = AlertSchema.model_validate(created_alert_model)
                    payload = {
                        "type": "NEW_ALERT_DETAILS",
                        "tenant_id": bundle.tenant_id,
                        "alert": alert_details.model_dump(mode="json"),
                    }
                    manager.broadcast_nowait(json.dumps(payload))
                except Exception as e_ws:
                    logger.error(f"Failed to broadcast file alert WebSocket message: {e_ws}", exc_info=True)

        try:
            is_mal = classification in {"blocked", "suspicious"}
            live_event = {
                "id": bundle.analysis_id,
                "type": "file_scan",
                "message": f"File '{bundle.filename}' {'flagged' if is_mal else 'scanned ok'}",
                "timestamp": bundle.analysis_timestamp.isoformat(),
                "isMalicious": is_mal,
                "tenant_id": bundle.tenant_id,
            }
            manager.broadcast_nowait(json.dumps(live_event))
        except Exception:
            pass

        defender_action_summary: Optional[Dict[str, Any]] = None
        defender_actions: Optional[List[str]] = None
        try:
            ir_service = self._incident_response_service_instance or IncidentResponseService.get_instance()
            risk_level = "High" if classification == "blocked" else ("Medium" if should_alert else "Low")
            defender_action_summary = ir_service.execute_actions(
                db=db,
                domain="file",
                entity_id=bundle.analysis_id,
                suggested_action=bundle.overall_assessment.recommended_action if bundle.overall_assessment else "ALLOW_UPLOAD",
                risk_level=risk_level,
                details={
                    "message": f"File '{bundle.filename}' decision: {bundle.overall_assessment.recommended_action if bundle.overall_assessment else 'ALLOW_UPLOAD'}.",
                    "structured_verdict": bundle.structured_verdict.model_dump(mode="json"),
                },
                create_alert_if_missing=False,
            )
            defender_actions = list(defender_action_summary.get("actions") or [])
        except Exception as e_ir:
            logger.error(f"Incident response action planning failed for file analysis: {e_ir}", exc_info=True)

        return defender_actions, defender_action_summary

    # --- THIS IS THE RESTORED LOGIC ---
    def _assess_risk(self,
                     filesize_kb: float,
                     is_allowed_type: bool,
                     detected_mime: str,
                     is_malicious_yara: bool,
                     yara_threat: Optional[str],
                     ml_result: Optional[MLScanResult],
                     macro_suspicious: bool = False,
                     pdf_suspicious: bool = False,
                     inner_yara_count: int = 0) -> FileAnalysisOverallAssessment:
        """Determines the overall risk of a file based on analysis results."""
        if filesize_kb > (MAX_FILE_SIZE_MB * 1024):
            return FileAnalysisOverallAssessment(overall_status="Rejected (Too Large)", risk_score=0.9, recommended_action="BLOCK_UPLOAD", reasoning=[f"File size ({filesize_kb:.2f} KB) exceeds limit."])
        if not is_allowed_type:
            return FileAnalysisOverallAssessment(overall_status="Unauthorized Type", risk_score=0.8, recommended_action="BLOCK_UPLOAD", reasoning=[f"File type '{detected_mime}' is not permitted."])
        if is_malicious_yara:
            return FileAnalysisOverallAssessment(overall_status="Malicious (YARA Match)", risk_score=0.95, recommended_action="BLOCK_AND_QUARANTINE", reasoning=[f"Threat detected by YARA rule: {yara_threat}."])
        if inner_yara_count > 0:
            return FileAnalysisOverallAssessment(overall_status="Malicious (YARA Match in Archive)", risk_score=0.9, recommended_action="BLOCK_AND_QUARANTINE", reasoning=["Threat detected by YARA inside archive contents."])
        if (ml_result and ml_result.is_suspicious_ml) or macro_suspicious or pdf_suspicious:
            score_info = ""
            if ml_result and ml_result.prediction_score_ml is not None:
                score_info = f"(Score: {ml_result.prediction_score_ml:.2f})"
            reasons: List[str] = []
            if ml_result and ml_result.is_suspicious_ml:
                reasons.append(f"Content flagged as suspicious by ML model {score_info}.")
            if macro_suspicious:
                reasons.append("Office macro indicators present.")
            if pdf_suspicious:
                reasons.append("PDF contains suspicious actions (e.g., JavaScript/OpenAction/Launch).")
            return FileAnalysisOverallAssessment(overall_status="Suspicious", risk_score=0.75, recommended_action="FLAG_FOR_REVIEW", reasoning=reasons or ["Heuristic indicators of malicious content found."])

        # If no issues are found, the file is considered safe.
        return FileAnalysisOverallAssessment(overall_status="Safe", risk_score=0.1, recommended_action="ALLOW_UPLOAD", reasoning=["File passed all security checks."])

    # --- Helper utilities ---
    def _is_zip_bytes(self, data: bytes) -> bool:
        return bool(data and len(data) >= 4 and data[:2] == b'PK')

    def _declared_extension(self, filename: Optional[str]) -> str:
        try:
            return os.path.splitext(str(filename or ""))[1].lower()
        except Exception:
            return ""

    def _file_signature_profile(self, data: bytes) -> Dict[str, Any]:
        """Return a small, explainable signature profile from magic bytes and first-page text."""
        if not data:
            return {"kind": "empty", "confidence": 1.0, "description": "Empty file"}
        head = data[:4096]
        stripped = head.lstrip()
        profile: Dict[str, Any] = {}
        if data.startswith(b"MZ"):
            profile = {"kind": "pe_executable", "confidence": 0.99, "description": "Windows PE executable header"}
        elif data.startswith(b"\x7fELF"):
            profile = {"kind": "elf_executable", "confidence": 0.99, "description": "ELF executable header"}
        elif data[:4] in {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"}:
            profile = {"kind": "macho_executable", "confidence": 0.99, "description": "Mach-O executable header"}
        elif data.startswith(b"%PDF") or b"%PDF" in data[:1024]:
            profile = {"kind": "pdf", "confidence": 0.98, "description": "PDF header"}
        elif self._is_zip_bytes(data):
            profile = {"kind": "zip_ooxml", "confidence": 0.95, "description": "ZIP/OOXML container header"}
        elif data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            profile = {"kind": "ole_cfb", "confidence": 0.95, "description": "OLE compound document header"}
        elif stripped.startswith(b"#!"):
            profile = {"kind": "script_text", "confidence": 0.85, "description": "Script shebang in text content"}
        else:
            try:
                text_head = head.decode("utf-8", errors="ignore").lower()
                script_hits = [
                    token
                    for token in (
                        "powershell",
                        "new-object system.net.sockets",
                        "invoke-expression",
                        "downloadstring",
                        "regsvr32",
                        "mshta",
                        "cmd.exe",
                        "/bin/sh",
                        "bash -i",
                        "wget ",
                        "curl ",
                    )
                    if token in text_head
                ]
                if script_hits:
                    profile = {
                        "kind": "script_text",
                        "confidence": 0.72,
                        "description": "Text contains command/script execution markers",
                        "markers": script_hits[:8],
                    }
                elif "<html" in text_head or "<!doctype html" in text_head or "<script" in text_head:
                    profile = {"kind": "html", "confidence": 0.7, "description": "HTML/text markup markers"}
            except Exception:
                pass
        return profile or {"kind": "unknown", "confidence": 0.0, "description": "No high-confidence signature"}

    def _extension_signature_mismatch(
        self,
        filename: Optional[str],
        detected_mime: str,
        data: bytes,
    ) -> Optional[Dict[str, Any]]:
        ext = self._declared_extension(filename)
        profile = self._file_signature_profile(data)
        kind = str(profile.get("kind") or "")
        if not ext or kind in {"unknown", "empty"}:
            return None

        reason: Optional[str] = None
        severity = "medium"
        if kind in EXECUTABLE_SIGNATURE_TYPES and ext not in {".exe", ".dll", ".scr", ".com"}:
            severity = "high"
            reason = f"Executable signature '{kind}' found in file declared as '{ext}'."
        elif ext == ".pdf" and kind != "pdf":
            if kind in {"script_text", "html", "zip_ooxml", "ole_cfb"}:
                severity = "high" if kind == "script_text" else "medium"
                reason = f"Extension '.pdf' does not match detected content signature '{kind}'."
        elif ext in ZIP_DOCUMENT_EXTENSIONS and kind != "zip_ooxml":
            severity = "high" if kind == "script_text" else "medium"
            reason = f"Office extension '{ext}' requires a ZIP/OOXML container, but content signature is '{kind}'."
        elif ext in OLE_DOCUMENT_EXTENSIONS and kind not in {"ole_cfb", "unknown"}:
            severity = "high" if kind == "script_text" else "medium"
            reason = f"Legacy Office extension '{ext}' requires an OLE document, but content signature is '{kind}'."
        elif ext in ARCHIVE_EXTENSIONS and kind != "zip_ooxml":
            if kind == "script_text":
                severity = "high"
                reason = f"Archive extension '{ext}' contains script text rather than a ZIP container."
        elif ext in SCRIPT_DISGUISE_EXTENSIONS and kind == "script_text":
            severity = "high"
            reason = f"Document/archive extension '{ext}' contains command/script text."

        if not reason:
            return None
        return {
            "extension": ext,
            "detected_mime": detected_mime,
            "signature": profile,
            "reason": reason,
            "severity": severity,
            "dangerous_signature": kind in EXECUTABLE_SIGNATURE_TYPES or severity == "high",
        }

    def _archive_path_is_unsafe(self, name: str) -> bool:
        normalized = str(name or "").replace("\\", "/")
        if normalized.startswith("/") or re.match(r"(?i)^[a-z]:/", normalized):
            return True
        parts = [part for part in normalized.split("/") if part]
        return any(part == ".." for part in parts)

    @staticmethod
    def _unique_strings(values: List[Any], limit: int = 40) -> List[str]:
        seen: set[str] = set()
        ordered: List[str] = []
        for value in values:
            text = str(value or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            ordered.append(text)
            if len(ordered) >= limit:
                break
        return ordered

    @staticmethod
    def _macro_risk_level(score: float) -> str:
        score_f = max(0.0, min(1.0, float(score or 0.0)))
        if score_f >= 0.90:
            return "critical"
        if score_f >= 0.75:
            return "high"
        if score_f >= 0.45:
            return "medium"
        if score_f > 0.0:
            return "low"
        return "none"

    @staticmethod
    def _macro_handling_for_level(level: str, *, source_trust: Optional[str] = None) -> str:
        level_lc = str(level or "").lower()
        trust_lc = str(source_trust or "").lower()
        if level_lc == "critical":
            return "block_request"
        if level_lc == "high":
            return "block_request"
        if level_lc == "medium":
            return "review"
        if level_lc == "low":
            return "monitor" if trust_lc == "trusted" else "review"
        return "allow"

    def _detect_macro_risk(self, macro_bytes: bytes) -> Dict[str, Any]:
        """Classify macro content by behavior indicators rather than macro presence alone."""
        try:
            text_original = (macro_bytes or b"").decode("utf-8", errors="ignore")
            text = text_original.lower()
        except Exception:
            text_original = ""
            text = ""
        if not text:
            return {
                "risky": False,
                "score": 0.0,
                "risk_level": "none",
                "indicators": [],
                "auto_exec_indicators": [],
                "execution_indicators": [],
                "network_indicators": [],
                "obfuscation_indicators": [],
                "external_reference_indicators": [],
                "embedded_object_indicators": [],
            }

        auto_patterns: List[Tuple[str, str]] = [
            ("AutoOpen", r"\bautoopen\b"),
            ("Auto_Open", r"\bauto_open\b"),
            ("Document_Open", r"\bdocument_open\b"),
            ("Workbook_Open", r"\bworkbook_open\b"),
            ("Presentation_Open", r"\bpresentation_open\b"),
            ("AutoClose", r"\bautoclose\b"),
            ("Document_Close", r"\bdocument_close\b"),
            ("Workbook_BeforeClose", r"\bworkbook_beforeclose\b"),
            ("AutoExec", r"\bautoexec\b"),
        ]
        execution_patterns: List[Tuple[str, str]] = [
            ("Shell", r"\bshell\s*\("),
            ("WScript.Shell", r"wscript\.shell"),
            ("CreateObject(WScript.Shell)", r"createobject\s*\(\s*[\"']wscript\.shell[\"']"),
            (".Run", r"\.run\b"),
            (".Exec", r"\.exec\b"),
            ("cmd.exe", r"\bcmd(?:\.exe)?\b"),
            ("powershell", r"\bpowershell(?:\.exe)?\b|\bpwsh\b"),
            ("mshta", r"\bmshta\b"),
            ("rundll32", r"\brundll32\b"),
            ("regsvr32", r"\bregsvr32\b"),
            ("wscript", r"\bwscript(?:\.exe)?\b"),
            ("cscript", r"\bcscript(?:\.exe)?\b"),
            ("certutil", r"\bcertutil\b"),
            ("bitsadmin", r"\bbitsadmin\b"),
        ]
        network_patterns: List[Tuple[str, str]] = [
            ("URLDownloadToFile", r"urldownloadtofile"),
            ("DownloadString", r"downloadstring"),
            ("XMLHTTP", r"xmlhttp"),
            ("WinHTTP", r"winhttp"),
            ("ADODB.Stream", r"adodb\.stream"),
            ("InternetOpen", r"internetopen"),
            ("http://", r"http://"),
            ("https://", r"https://"),
            ("ftp://", r"ftp://"),
            ("pastebin", r"pastebin"),
            ("raw.githubusercontent", r"raw\.githubusercontent"),
            ("discordapp", r"discordapp|discord\.com/api/webhooks"),
            ("telegram", r"telegram"),
        ]
        obfuscation_patterns: List[Tuple[str, str]] = [
            ("Chr", r"\bchrw?\s*\("),
            ("StrReverse", r"\bstrreverse\s*\("),
            ("Base64", r"base64|frombase64string"),
            ("Execute", r"\bexecute\s*\("),
            ("Eval", r"\beval\s*\("),
            ("CallByName", r"\bcallbyname\s*\("),
            ("long concatenated strings", r"(?:[\"'][^\"']{20,}[\"']\s*&\s*){3,}"),
            ("hex/base64-looking blob", r"\b[a-z0-9+/]{160,}={0,2}\b|\b(?:0x[a-f0-9]{2}[\s,]+){12,}"),
        ]
        persistence_patterns: List[Tuple[str, str]] = [
            ("Environ", r"\benviron\s*\("),
            ("AppData", r"appdata"),
            ("Startup", r"startup"),
            ("Registry", r"registry|regwrite"),
            ("WMI", r"winmgmts|getobject\s*\(\s*[\"']winmgmts"),
        ]
        dde_patterns: List[Tuple[str, str]] = [
            ("DDE", r"\bdde\b"),
            ("DDEAUTO", r"\bddeauto\b"),
            ("INCLUDEPICTURE remote URL", r"includepicture[^\r\n]{0,200}https?://"),
            ("LINK remote field", r"\blink[^\r\n]{0,200}(?:https?://|\\\\|file:)"),
        ]

        def hits(patterns: List[Tuple[str, str]]) -> List[str]:
            return [label for label, pattern in patterns if re.search(pattern, text, flags=re.IGNORECASE)]

        auto_hits = hits(auto_patterns)
        execution_hits = hits(execution_patterns)
        network_hits = hits(network_patterns)
        obfuscation_hits = hits(obfuscation_patterns)
        persistence_hits = hits(persistence_patterns)
        dde_hits = hits(dde_patterns)

        score = 0.25 if any((auto_hits, execution_hits, network_hits, obfuscation_hits, persistence_hits, dde_hits)) else 0.0
        if auto_hits:
            score = max(score, 0.55)
        if execution_hits:
            score = max(score, 0.70)
        if network_hits:
            score = max(score, 0.65)
        if obfuscation_hits:
            score = max(score, 0.60)
        if dde_hits:
            score = max(score, 0.70)
        if auto_hits and execution_hits:
            score = max(score, 0.82)
        if auto_hits and any(x.lower() in {"powershell", "cmd.exe", "mshta", "regsvr32", "rundll32"} for x in execution_hits):
            score = max(score, 0.92)
        if network_hits and execution_hits:
            score = max(score, 0.92)
        if obfuscation_hits and execution_hits:
            score = max(score, 0.85)
        if dde_hits and execution_hits:
            score = max(score, 0.92)

        indicators = self._unique_strings(
            auto_hits + execution_hits + network_hits + obfuscation_hits + persistence_hits + dde_hits,
            limit=30,
        )
        level = self._macro_risk_level(score)
        return {
            "risky": score >= 0.75,
            "score": round(score, 4),
            "risk_level": level,
            "indicators": indicators,
            "auto_exec": bool(auto_hits),
            "auto_exec_indicators": auto_hits,
            "execution_indicators": execution_hits + persistence_hits,
            "network_indicators": network_hits,
            "obfuscation_indicators": obfuscation_hits,
            "external_reference_indicators": dde_hits,
            "embedded_object_indicators": [],
        }

    def _safe_zip_scan(self, data: bytes) -> Dict[str, Any]:
        """Scan a ZIP/OOXML archive in-memory, enforcing safety limits and nested recursion.
        Returns details: inner YARA matches, macro indicators, stats, and errors.
        """
        details: Dict[str, Any] = {
            "inner_yara_matches": [],  # list of { path, rules: [..] }
            "macro_present": False,
            "macro_paths": [],
            "macro_risky": False,
            "macro_risk_paths": [],
            "macro_risk_score": 0.0,
            "macro_risk_level": "none",
            "macro_indicators": [],
            "macro_auto_exec_indicators": [],
            "macro_execution_indicators": [],
            "macro_network_indicators": [],
            "macro_obfuscation_indicators": [],
            "external_reference_indicators": [],
            "embedded_object_indicators": [],
            "suspicious_archive": False,
            "suspicious_reasons": [],
            "suspicious_entries": [],
            "stats": {
                "files": 0,
                "skipped_large": 0,
                "total_bytes": 0,
                "nested_archives": 0,
                "depth_reached": 0,
                "encrypted_entries": 0,
                "max_compression_ratio": 0.0,
            },
            "errors": []
        }

        def add_archive_reason(reason: str, path: Optional[str] = None) -> None:
            details["suspicious_archive"] = True
            if reason not in details["suspicious_reasons"]:
                details["suspicious_reasons"].append(reason)
            if path and path not in details["suspicious_entries"]:
                details["suspicious_entries"].append(path)

        def scan_zip_bytes(zip_bytes: bytes, prefix: str, depth: int) -> None:
            try:
                with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                    details["stats"]["depth_reached"] = max(details["stats"].get("depth_reached", 0), depth)
                    for i, zi in enumerate(zf.infolist()):
                        if i >= MAX_ARCHIVE_FILES:
                            details["errors"].append("Archive file limit reached; remaining entries skipped.")
                            break
                        # Macro presence in OOXML
                        lower_name = zi.filename.lower()
                        full_name = prefix + zi.filename
                        if self._archive_path_is_unsafe(zi.filename):
                            add_archive_reason("path_traversal_entry", full_name)
                        if bool(getattr(zi, "flag_bits", 0) & 0x1):
                            details["stats"]["encrypted_entries"] += 1
                            add_archive_reason("encrypted_entry", full_name)
                        try:
                            _, entry_ext = os.path.splitext(lower_name)
                            if entry_ext in ARCHIVE_HIGH_RISK_EXTENSIONS:
                                add_archive_reason(f"high_risk_entry_extension:{entry_ext}", full_name)
                        except Exception:
                            pass
                        compressed_size = max(1, int(getattr(zi, "compress_size", 0) or 1))
                        ratio = float(zi.file_size or 0) / float(compressed_size)
                        details["stats"]["max_compression_ratio"] = round(
                            max(float(details["stats"].get("max_compression_ratio") or 0.0), ratio),
                            2,
                        )
                        if zi.file_size >= (1024 * 1024) and ratio >= ARCHIVE_SUSPICIOUS_COMPRESSION_RATIO:
                            add_archive_reason("high_compression_ratio", full_name)

                        is_macro_entry = (
                            lower_name.endswith("vbaproject.bin") or
                            lower_name.endswith("/vbaproject.bin") or
                            "/vba/" in lower_name
                        )
                        if is_macro_entry:
                            details["macro_present"] = True
                            details["macro_paths"].append(full_name)
                        # Size limits
                        if zi.file_size > MAX_ENTRY_SIZE_MB * 1024 * 1024:
                            details["stats"]["skipped_large"] += 1
                            continue
                        try:
                            with zf.open(zi) as f:
                                content = f.read()
                                details["stats"]["files"] += 1
                                details["stats"]["total_bytes"] += len(content)
                                if (details["stats"]["total_bytes"] > MAX_ARCHIVE_TOTAL_UNCOMPRESSED_MB * 1024 * 1024):
                                    details["errors"].append("Archive total uncompressed size limit exceeded; stopping scan.")
                                    return
                                if is_macro_entry:
                                    macro_risk = self._detect_macro_risk(content)
                                    indicators = [str(i) for i in (macro_risk.get("indicators") or []) if str(i)]
                                    for indicator in indicators:
                                        if indicator not in details["macro_indicators"]:
                                            details["macro_indicators"].append(indicator)
                                    for src_key, dst_key in (
                                        ("auto_exec_indicators", "macro_auto_exec_indicators"),
                                        ("execution_indicators", "macro_execution_indicators"),
                                        ("network_indicators", "macro_network_indicators"),
                                        ("obfuscation_indicators", "macro_obfuscation_indicators"),
                                    ):
                                        for indicator in [str(i) for i in (macro_risk.get(src_key) or []) if str(i)]:
                                            if indicator not in details[dst_key]:
                                                details[dst_key].append(indicator)
                                    try:
                                        score = float(macro_risk.get("score") or 0.0)
                                        if score > float(details.get("macro_risk_score") or 0.0):
                                            details["macro_risk_score"] = round(score, 4)
                                            details["macro_risk_level"] = str(macro_risk.get("risk_level") or self._macro_risk_level(score))
                                    except Exception:
                                        pass
                                    if bool(macro_risk.get("risky")):
                                        details["macro_risky"] = True
                                        details["macro_risk_paths"].append(full_name)
                                if lower_name.endswith(".rels") or lower_name.endswith(".xml"):
                                    try:
                                        xml_text = content[:IOC_TEXT_SCAN_LIMIT_BYTES].decode("utf-8", errors="ignore")
                                        xml_lc = xml_text.lower()
                                        if "targetmode=\"external\"" in xml_lc or "targetmode='external'" in xml_lc:
                                            targets = re.findall(
                                                r"(?is)\btarget\s*=\s*['\"]([^'\"]+)['\"]",
                                                xml_text[:200000],
                                            )
                                            external_targets = [
                                                t
                                                for t in targets
                                                if re.match(r"(?i)^(?:https?://|file:|\\\\|smb://)", str(t or "").strip())
                                            ]
                                            if external_targets:
                                                for target in external_targets[:10]:
                                                    label = f"{full_name}:external_relationship:{target}"
                                                    if label not in details["external_reference_indicators"]:
                                                        details["external_reference_indicators"].append(label)
                                                add_archive_reason("external_relationship", full_name)
                                        if "attachedtemplate" in xml_lc and re.search(r"(?i)(https?://|file:|\\\\|smb://)", xml_text):
                                            label = f"{full_name}:external_template"
                                            if label not in details["external_reference_indicators"]:
                                                details["external_reference_indicators"].append(label)
                                            add_archive_reason("external_template", full_name)
                                        if "ddeauto" in xml_lc or re.search(r"(?i)\bdde\b", xml_text):
                                            label = f"{full_name}:dde_field"
                                            if label not in details["external_reference_indicators"]:
                                                details["external_reference_indicators"].append(label)
                                            add_archive_reason("dde_field", full_name)
                                        if "includepicture" in xml_lc and re.search(r"(?i)https?://", xml_text):
                                            label = f"{full_name}:remote_includepicture"
                                            if label not in details["external_reference_indicators"]:
                                                details["external_reference_indicators"].append(label)
                                            add_archive_reason("remote_includepicture", full_name)
                                        if "customui" in xml_lc and "onaction" in xml_lc:
                                            label = f"{full_name}:customui_callback"
                                            if label not in details["embedded_object_indicators"]:
                                                details["embedded_object_indicators"].append(label)
                                            add_archive_reason("customui_callback", full_name)
                                    except Exception:
                                        pass
                                if (
                                    "/activex/" in lower_name
                                    or "/embeddings/" in lower_name
                                    or "oleobject" in lower_name
                                    or lower_name.endswith(".bin") and ("embeddings/" in lower_name or "activex/" in lower_name)
                                ):
                                    label = f"{full_name}:embedded_ole_or_activex"
                                    if label not in details["embedded_object_indicators"]:
                                        details["embedded_object_indicators"].append(label)
                                    add_archive_reason("embedded_ole_or_activex", full_name)
                                # Recurse into nested archives within depth limit
                                if self._is_zip_bytes(content) and depth < MAX_ARCHIVE_DEPTH:
                                    details["stats"]["nested_archives"] += 1
                                    scan_zip_bytes(content, prefix + zi.filename + ":", depth + 1)
                                # YARA scan inner file
                                if self._yara_rules and content:
                                    try:
                                        ymatches = self._yara_rules.match(data=content)
                                        if ymatches:
                                            entry: Dict[str, Any] = {
                                                "path": prefix + zi.filename,
                                                "rules": [m.rule for m in ymatches]
                                            }
                                            try:
                                                entry["rules_info"] = [
                                                    {
                                                        "rule": m.rule,
                                                        "description": (m.meta or {}).get('description'),
                                                        "category": (m.meta or {}).get('category'),
                                                        "threat_level": (m.meta or {}).get('threat_level'),
                                                    }
                                                    for m in ymatches
                                                ]
                                            except Exception:
                                                pass
                                            details["inner_yara_matches"].append(entry)
                                    except Exception as e_y:
                                        details["errors"].append(f"YARA scan error for {prefix + zi.filename}: {e_y}")
                        except Exception as e_entry:
                            details["errors"].append(f"Failed to read entry {prefix + zi.filename}: {e_entry}")
            except Exception as e_zip:
                details["errors"].append(f"Failed to open as ZIP/OOXML: {e_zip}")

        scan_zip_bytes(data, prefix="", depth=1)
        return details

    def _legacy_ole_macro_scan(self, data: bytes) -> Dict[str, Any]:
        """Best-effort static legacy OLE macro scan. Never executes macros."""
        details: Dict[str, Any] = {
            "macro_present": False,
            "macro_container_type": None,
            "macro_risk_score": 0.0,
            "macro_risk_level": "none",
            "macro_indicators": [],
            "auto_exec_indicators": [],
            "execution_indicators": [],
            "network_indicators": [],
            "obfuscation_indicators": [],
            "external_reference_indicators": [],
            "embedded_object_indicators": [],
            "limitations": [],
            "detected_by": None,
        }
        if not data:
            return details

        extracted_sources: List[bytes] = []
        try:
            from oletools.olevba3 import VBA_Parser  # type: ignore
            parser = None
            try:
                parser = VBA_Parser(filename=None, data=data)
                has_macros = bool(parser.detect_vba_macros())
                if has_macros:
                    details["macro_present"] = True
                    details["macro_container_type"] = "legacy_ole_vba"
                    details["detected_by"] = "olevba3"
                    try:
                        for macro_tuple in parser.extract_macros():
                            try:
                                source = macro_tuple[-1]
                                if isinstance(source, str):
                                    extracted_sources.append(source.encode("utf-8", errors="ignore"))
                                elif isinstance(source, bytes):
                                    extracted_sources.append(source)
                            except Exception:
                                continue
                    except Exception as exc:
                        details["limitations"].append(f"Legacy OLE macro source extraction failed: {str(exc)[:160]}")
                    try:
                        for finding in parser.analyze_macros() or []:
                            text = " ".join(str(part) for part in finding if part is not None)
                            if text:
                                details["macro_indicators"].append(text[:160])
                    except Exception:
                        pass
            finally:
                try:
                    if parser is not None:
                        parser.close()
                except Exception:
                    pass
        except Exception:
            details["limitations"].append("Legacy OLE macro deep parsing unavailable because oletools is not installed.")

        lower_bytes = data[:IOC_TEXT_SCAN_LIMIT_BYTES].lower()
        fallback_markers = [
            b"autoopen",
            b"document_open",
            b"workbook_open",
            b"autoexec",
            b"wscript.shell",
            b"createobject(\"wscript.shell\")",
            b"powershell",
            b"urldownloadtofile",
            b"xmlhttp",
            b"ddeauto",
        ]
        if any(marker in lower_bytes for marker in fallback_markers):
            details["macro_present"] = True
            details["macro_container_type"] = details.get("macro_container_type") or "legacy_ole_vba"
            details["detected_by"] = details.get("detected_by") or "heuristic_markers"
            extracted_sources.append(data[:IOC_TEXT_SCAN_LIMIT_BYTES])

        for source in extracted_sources[:20]:
            risk = self._detect_macro_risk(source)
            score = float(risk.get("score") or 0.0)
            if score > float(details.get("macro_risk_score") or 0.0):
                details["macro_risk_score"] = round(score, 4)
                details["macro_risk_level"] = str(risk.get("risk_level") or self._macro_risk_level(score))
            for src_key, dst_key in (
                ("indicators", "macro_indicators"),
                ("auto_exec_indicators", "auto_exec_indicators"),
                ("execution_indicators", "execution_indicators"),
                ("network_indicators", "network_indicators"),
                ("obfuscation_indicators", "obfuscation_indicators"),
                ("external_reference_indicators", "external_reference_indicators"),
                ("embedded_object_indicators", "embedded_object_indicators"),
            ):
                details[dst_key] = self._unique_strings(list(details.get(dst_key) or []) + list(risk.get(src_key) or []))

        details["macro_indicators"] = self._unique_strings(list(details.get("macro_indicators") or []), limit=40)
        return details

    def _build_macro_defense_result(
        self,
        *,
        filename: Optional[str],
        detected_mime: str,
        zip_details: Optional[Dict[str, Any]],
        legacy_details: Optional[Dict[str, Any]],
        signature_mismatch_info: Optional[Dict[str, Any]],
        source_metadata: Optional[Dict[str, Any]] = None,
    ) -> MacroDefenseResult:
        """Build professor-defensible macro evidence without executing Office content."""
        ext = self._declared_extension(filename)
        metadata = source_metadata if isinstance(source_metadata, dict) else {}
        motw_zone = str(metadata.get("motw_zone") or metadata.get("source_zone") or "").strip().lower() or None
        source_trust = str(metadata.get("source_trust") or "").strip().lower() or None
        upload_source = str(metadata.get("upload_source") or "").strip().lower()
        if not source_trust:
            if motw_zone in {"internet", "restricted", "untrusted", "3", "4"} or upload_source in {"internet", "email", "external"}:
                source_trust = "untrusted"
            elif bool(metadata.get("trusted_location")):
                source_trust = "trusted"
            else:
                source_trust = "unknown"
        signed_macro = metadata.get("signed_macro")
        trusted_publisher = metadata.get("trusted_publisher")
        signed_value = bool(signed_macro) if isinstance(signed_macro, bool) else None
        trusted_publisher_value = bool(trusted_publisher) if isinstance(trusted_publisher, bool) else None

        zip_payload = zip_details if isinstance(zip_details, dict) else {}
        legacy_payload = legacy_details if isinstance(legacy_details, dict) else {}
        macro_paths = [str(x) for x in (zip_payload.get("macro_paths") or []) if str(x)]
        ooxml_macro_present = bool(zip_payload.get("macro_present"))
        legacy_macro_present = bool(legacy_payload.get("macro_present"))
        macro_present = bool(ooxml_macro_present or legacy_macro_present)

        container_type = None
        if ooxml_macro_present:
            container_type = "ooxml_vba_project"
        elif legacy_macro_present:
            container_type = str(legacy_payload.get("macro_container_type") or "legacy_ole_vba")
        elif ext in MACRO_ENABLED_OOXML_EXTENSIONS:
            container_type = "macro_enabled_extension_without_detected_container"

        auto_exec = self._unique_strings(
            list(zip_payload.get("macro_auto_exec_indicators") or []) + list(legacy_payload.get("auto_exec_indicators") or [])
        )
        execution = self._unique_strings(
            list(zip_payload.get("macro_execution_indicators") or []) + list(legacy_payload.get("execution_indicators") or [])
        )
        network = self._unique_strings(
            list(zip_payload.get("macro_network_indicators") or []) + list(legacy_payload.get("network_indicators") or [])
        )
        obfuscation = self._unique_strings(
            list(zip_payload.get("macro_obfuscation_indicators") or []) + list(legacy_payload.get("obfuscation_indicators") or [])
        )
        external_refs = self._unique_strings(
            list(zip_payload.get("external_reference_indicators") or []) + list(legacy_payload.get("external_reference_indicators") or [])
        )
        embedded_objects = self._unique_strings(
            list(zip_payload.get("embedded_object_indicators") or []) + list(legacy_payload.get("embedded_object_indicators") or [])
        )
        macro_indicators = self._unique_strings(
            list(zip_payload.get("macro_indicators") or []) + list(legacy_payload.get("macro_indicators") or [])
        )

        score = 0.0
        evidence_reasons: List[str] = []
        limitations: List[str] = []
        if ooxml_macro_present:
            score = max(score, 0.50)
            evidence_reasons.append("OOXML package contains vbaProject.bin macro container.")
        if legacy_macro_present:
            score = max(score, 0.50)
            evidence_reasons.append("Legacy Office/OLE macro evidence detected by static parsing or markers.")
        if ext in MACRO_ENABLED_OOXML_EXTENSIONS and not ooxml_macro_present:
            score = max(score, 0.45)
            evidence_reasons.append("Macro-enabled Office extension supplied without a detected vbaProject.bin container; source consistency should be reviewed.")
        if ext in NON_MACRO_OOXML_EXTENSIONS and ooxml_macro_present:
            score = max(score, 0.85)
            evidence_reasons.append("Macro project found inside a non-macro OOXML extension; normal .docx/.xlsx/.pptx files should not contain vbaProject.bin.")
        if signature_mismatch_info:
            evidence_reasons.append(str(signature_mismatch_info.get("reason") or "Extension/content mismatch detected."))
        if auto_exec:
            score = max(score, 0.65)
            evidence_reasons.append(f"Auto-execution macro indicators: {', '.join(auto_exec[:6])}.")
        if execution:
            score = max(score, 0.80)
            evidence_reasons.append(f"Macro execution indicators: {', '.join(execution[:6])}.")
        if network:
            score = max(score, 0.75)
            evidence_reasons.append(f"Network/download macro indicators: {', '.join(network[:6])}.")
        if obfuscation:
            score = max(score, 0.70)
            evidence_reasons.append(f"Macro obfuscation indicators: {', '.join(obfuscation[:6])}.")
        if external_refs:
            score = max(score, 0.80)
            evidence_reasons.append(f"External template/relationship indicators: {', '.join(external_refs[:4])}.")
        if embedded_objects:
            score = max(score, 0.70)
            evidence_reasons.append(f"Embedded OLE/ActiveX indicators: {', '.join(embedded_objects[:4])}.")
        if auto_exec and execution:
            score = max(score, 0.85)
        if auto_exec and any(str(x).lower() in {"powershell", "cmd.exe", "mshta", "regsvr32", "rundll32"} for x in execution):
            score = max(score, 0.92)
            evidence_reasons.append("Auto-execution combined with command interpreter or LOLBin execution is critical macro behaviour.")
        if network and execution:
            score = max(score, 0.92)
            evidence_reasons.append("Network/download indicators combined with execution are critical macro behaviour.")
        if obfuscation and execution:
            score = max(score, 0.85)
            evidence_reasons.append("Obfuscation combined with execution is high-risk macro behaviour.")

        zip_score = float(zip_payload.get("macro_risk_score") or 0.0)
        legacy_score = float(legacy_payload.get("macro_risk_score") or 0.0)
        score = max(score, zip_score, legacy_score)

        trusted_benign = bool(
            macro_present
            and signed_value is True
            and trusted_publisher_value is True
            and not any((auto_exec, execution, network, obfuscation, external_refs, embedded_objects))
        )
        if trusted_benign:
            score = min(max(score, 0.20), 0.35)
            evidence_reasons.append("Macro is reported signed by a trusted publisher and no risky macro behaviour was found.")
        elif macro_present and not any((auto_exec, execution, network, obfuscation, external_refs, embedded_objects)):
            evidence_reasons.append("Macro container present, but no auto-execution, shell execution, network download, or obfuscation indicators were found.")

        if not metadata:
            limitations.append("Source-zone / Mark-of-the-Web metadata was not supplied by the upload context.")
            limitations.append("Signed macro and trusted-publisher metadata were not supplied by the upload context.")
        elif motw_zone is None:
            limitations.append("Mark-of-the-Web/source-zone metadata was not supplied by the upload context.")
        if ext in MACRO_CAPABLE_LEGACY_EXTENSIONS:
            limitations.extend([str(x) for x in (legacy_payload.get("limitations") or []) if str(x)])
        limitations.append("Static macro defence does not execute macros and does not claim sandbox detonation.")
        limitations.append("Block/quarantine labels are requests or recommendations unless an enforcement integration performs durable action.")

        if motw_zone in {"internet", "restricted", "untrusted", "3", "4"} and macro_present:
            score = max(score, 0.65)
            evidence_reasons.append("Macro-bearing file is marked or supplied as internet/restricted-source content.")
        if source_trust == "trusted" and signed_value is True and trusted_publisher_value is True and score < 0.75:
            score = min(score, 0.35)

        score = round(max(0.0, min(1.0, score)), 4)
        level = self._macro_risk_level(score)
        handling = self._macro_handling_for_level(level, source_trust=source_trust)
        return MacroDefenseResult(
            macro_present=macro_present,
            macro_container_type=container_type,
            macro_risk_score=score,
            macro_risk_level=level,
            macro_indicators=macro_indicators,
            auto_exec_indicators=auto_exec,
            execution_indicators=execution,
            network_indicators=network,
            obfuscation_indicators=obfuscation,
            external_reference_indicators=external_refs,
            embedded_object_indicators=embedded_objects,
            motw_zone=motw_zone,
            source_trust=source_trust,
            signed_macro=signed_value,
            trusted_publisher=trusted_publisher_value,
            recommended_handling=handling,
            evidence_reasons=self._unique_strings(evidence_reasons, limit=20),
            limitations=self._unique_strings(limitations, limit=12),
        )

    @staticmethod
    def _apply_macro_defense_to_assessment(
        overall_assessment: FileAnalysisOverallAssessment,
        macro_defense: Optional[MacroDefenseResult],
    ) -> FileAnalysisOverallAssessment:
        if macro_defense is None:
            return overall_assessment
        score = float(macro_defense.macro_risk_score or 0.0)
        level = str(macro_defense.macro_risk_level or "none").lower()
        if score <= 0.0 or level == "none":
            return overall_assessment

        current = float(overall_assessment.risk_score or 0.0)
        reasons = list(overall_assessment.reasoning or [])
        for reason in list(macro_defense.evidence_reasons or [])[:8]:
            if reason not in reasons:
                reasons.append(reason)

        if level == "critical":
            overall_assessment.overall_status = "Critical Macro Behaviour Detected"
            overall_assessment.risk_score = max(current, 0.92, score)
            overall_assessment.recommended_action = "BLOCK_REQUEST"
        elif level == "high":
            if "malicious" not in str(overall_assessment.overall_status or "").lower():
                overall_assessment.overall_status = "Risky Macro Detected"
            overall_assessment.risk_score = max(current, 0.80, score)
            overall_assessment.recommended_action = "BLOCK_REQUEST"
        elif level == "medium":
            if str(overall_assessment.overall_status or "").lower() == "safe":
                overall_assessment.overall_status = "Macro Present - Review Required"
            overall_assessment.risk_score = max(current, 0.60, score)
            if str(overall_assessment.recommended_action or "").upper().startswith("ALLOW"):
                overall_assessment.recommended_action = "FLAG_FOR_REVIEW"
        elif level == "low":
            if str(overall_assessment.overall_status or "").lower() == "safe":
                overall_assessment.overall_status = "Macro Present - Monitor"
            overall_assessment.risk_score = max(current, 0.25, score)
            if str(overall_assessment.recommended_action or "").upper().startswith("ALLOW") and macro_defense.recommended_handling == "review":
                overall_assessment.recommended_action = "FLAG_FOR_REVIEW"

        overall_assessment.reasoning = reasons or overall_assessment.reasoning
        return overall_assessment

    def _pdfid_scan(self, data: bytes) -> Tuple[bool, List[str], Dict[str, int]]:
        """PDFiD-style keyword counting. Returns (suspicious, matched_keywords, counts)."""
        if not data:
            return False, [], {}
        try:
            head = data[:8]
            if not (head.startswith(b"%PDF") or b"%PDF" in data[:1024]):
                return False, [], {}
        except Exception:
            return False, [], {}
        keys = [b"/JS", b"/JavaScript", b"/AA", b"/OpenAction", b"/Launch", b"/EmbeddedFile", b"/AcroForm", b"/RichMedia", b"/Names", b"/URI", b"/GoTo", b"/ObjStm"]
        counts: Dict[str, int] = {}
        matched: List[str] = []
        for k in keys:
            c = data.count(k)
            if c:
                sk = k.decode('ascii', errors='ignore')
                counts[sk] = c
                matched.append(sk)
        suspicious = False
        if counts.get('/Launch', 0) > 0:
            suspicious = True
        if (counts.get('/JS', 0) + counts.get('/JavaScript', 0)) > 0 and (counts.get('/OpenAction', 0) + counts.get('/AA', 0)) > 0:
            suspicious = True
        if counts.get('/EmbeddedFile', 0) > 0 and (counts.get('/JS', 0) + counts.get('/JavaScript', 0) > 0):
            suspicious = True
        if counts.get('/ObjStm', 0) > 0 and (counts.get('/JS', 0) + counts.get('/JavaScript', 0) > 0):
            suspicious = True
        return suspicious, matched, counts

    async def analyze_file(
        self,
        db: Session,
        file: UploadFile,
        tenant_id: Optional[str] = None,
        source_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        effective_tenant_id = str(tenant_id or "").strip() or DEFAULT_TENANT_ID
        analysis_id = f"file-{uuid.uuid4()}"
        analysis_timestamp = datetime.now(timezone.utc)
        errors_encountered: List[str] = []

        file_content = await file.read()
        filesize_kb = len(file_content) / 1024
        is_oversize_upload = filesize_kb > (MAX_FILE_SIZE_MB * 1024)

        detected_mime = magic.from_buffer(file_content, mime=True) if file_content else "application/x-empty"
        is_allowed_type = detected_mime in ALLOWED_MIME_TYPES
        type_validation_result = FileTypeValidationResult(detected_mime_type=detected_mime, is_allowed_type=is_allowed_type)

        # One-time upgrade to multi-file YARA compilation if available
        try:
            if self._yara_rules and not getattr(self, "_yara_multi", False):
                rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'yara_rules')
                if os.path.isdir(rules_dir):
                    file_map = {fname: os.path.join(rules_dir, fname) for fname in os.listdir(rules_dir) if fname.lower().endswith('.yar')}
                    if file_map:
                        self._yara_rules = yara.compile(filepaths=file_map)
                        setattr(self, "_yara_multi", True)
        except Exception:
            pass

        yara_matches = (
            self._yara_rules.match(data=file_content)
            if self._yara_rules and file_content and not is_oversize_upload
            else []
        )
        outer_yara_rules = [m.rule for m in yara_matches] if yara_matches else []
        # Prepare malware scan details; we will enrich as we go
        malware_scan_details: Dict[str, Any] = {}
        if is_oversize_upload:
            malware_scan_details["scan_skip_reason"] = "file_size_limit"
        signature_mismatch_info = self._extension_signature_mismatch(file.filename or "", detected_mime, file_content)
        dangerous_file_signature = bool(signature_mismatch_info and signature_mismatch_info.get("dangerous_signature"))
        try:
            malware_scan_details["file_signature"] = {
                "profile": self._file_signature_profile(file_content),
                "extension_mismatch": signature_mismatch_info,
            }
        except Exception:
            pass
        if outer_yara_rules:
            malware_scan_details["outer_yara_matches"] = outer_yara_rules
            try:
                malware_scan_details["outer_rule_info"] = [
                    {
                        "rule": m.rule,
                        "description": (m.meta or {}).get('description'),
                        "category": (m.meta or {}).get('category'),
                        "threat_level": (m.meta or {}).get('threat_level'),
                    }
                    for m in yara_matches
                ]
            except Exception:
                pass

        # Classify YARA matches by category + threat_level to reduce false positives.
        poc_yara_rules: List[str] = []
        dangerous_yara_rules: List[str] = []
        suspicious_yara_rules: List[str] = []
        yara_categories: Dict[str, str] = {}
        yara_threat_levels: Dict[str, str] = {}
        try:
            for m in (yara_matches or []):
                cat = str((m.meta or {}).get('category', '') or '')
                lvl = str((m.meta or {}).get('threat_level', '') or '').strip().lower()
                yara_categories[m.rule] = cat
                yara_threat_levels[m.rule] = lvl
                if 'poc' in cat.lower():
                    poc_yara_rules.append(m.rule)
                elif lvl in MALICIOUS_YARA_THREAT_LEVELS:
                    dangerous_yara_rules.append(m.rule)
                elif lvl in SUSPICIOUS_YARA_THREAT_LEVELS:
                    suspicious_yara_rules.append(m.rule)
                else:
                    # Backward compatible default: unknown severity remains dangerous.
                    dangerous_yara_rules.append(m.rule)
        except Exception:
            pass
        if yara_categories:
            malware_scan_details["yara_categories"] = yara_categories
        if yara_threat_levels:
            malware_scan_details["yara_threat_levels"] = yara_threat_levels
        if suspicious_yara_rules:
            malware_scan_details["suspicious_yara_matches"] = suspicious_yara_rules

        # Optional ClamAV scan
        clam = {"available": False}
        if not is_oversize_upload:
            try:
                clam = self._clamav_scan(file_content)
                if clam.get('available'):
                    malware_scan_details["clamav"] = clam
            except Exception:
                pass

        # PDF scanning (PDFiD-style)
        pdf_suspicious = False
        pdf_hits: List[str] = []
        if (not is_oversize_upload) and (detected_mime == "application/pdf" or (file_content[:4] == b"%PDF")):
            pdf_suspicious, pdf_hits, pdf_counts = self._pdfid_scan(file_content)
            if pdf_hits:
                malware_scan_details["pdfid"] = {"suspicious": pdf_suspicious, "keywords": pdf_hits, "counts": pdf_counts}

        # Archive/OOXML recursive scan (ZIP-based)
        inner_yara_matches: List[Dict[str, Any]] = []
        macro_present = False
        macro_risky = False
        archive_suspicious = False
        zip_details: Dict[str, Any] = {}
        legacy_macro_details: Dict[str, Any] = {}
        if (not is_oversize_upload) and (detected_mime in {"application/zip",
                             "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                             "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                             "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                             "application/vnd.ms-word.document.macroEnabled.12",
                             "application/vnd.ms-excel.sheet.macroEnabled.12",
                             "application/vnd.ms-powerpoint.presentation.macroEnabled.12"} or self._is_zip_bytes(file_content)):
            zip_details = self._safe_zip_scan(file_content)
            inner_yara_matches = zip_details.get("inner_yara_matches", [])
            macro_present = bool(zip_details.get("macro_present"))
            macro_risky = bool(zip_details.get("macro_risky"))
            archive_suspicious = bool(zip_details.get("suspicious_archive"))
            malware_scan_details["archive"] = {
                "stats": zip_details.get("stats", {}),
                "errors": zip_details.get("errors", []),
                "suspicious": archive_suspicious,
                "suspicious_reasons": zip_details.get("suspicious_reasons", []),
                "suspicious_entries": zip_details.get("suspicious_entries", [])[:25],
            }
            if inner_yara_matches:
                malware_scan_details["inner_yara_matches"] = inner_yara_matches
            if macro_present:
                malware_scan_details["macro"] = {
                    "present": True,
                    "paths": zip_details.get("macro_paths", []),
                    "risky": macro_risky,
                    "risk_paths": zip_details.get("macro_risk_paths", []),
                    "indicators": zip_details.get("macro_indicators", []),
                    "auto_exec_indicators": zip_details.get("macro_auto_exec_indicators", []),
                    "execution_indicators": zip_details.get("macro_execution_indicators", []),
                    "network_indicators": zip_details.get("macro_network_indicators", []),
                    "obfuscation_indicators": zip_details.get("macro_obfuscation_indicators", []),
                }
            if zip_details.get("external_reference_indicators") or zip_details.get("embedded_object_indicators"):
                malware_scan_details.setdefault("macro", {}).update({
                    "external_reference_indicators": zip_details.get("external_reference_indicators", []),
                    "embedded_object_indicators": zip_details.get("embedded_object_indicators", []),
                })

        # Legacy OLE macro heuristic (best-effort if not an OOXML zip)
        macro_suspicious = bool(macro_risky)
        if (not is_oversize_upload) and detected_mime in {"application/msword", "application/vnd.ms-excel", "application/vnd.ms-powerpoint"}:
            legacy_macro_details = self._legacy_ole_macro_scan(file_content)
            if legacy_macro_details.get("macro_present"):
                macro_present = True
                macro_suspicious = bool(float(legacy_macro_details.get("macro_risk_score") or 0.0) >= 0.75)
                malware_scan_details["macro"] = {
                    "present": True,
                    "paths": [],
                    "risky": macro_suspicious,
                    "risk_paths": [],
                    "detected_by": legacy_macro_details.get("detected_by"),
                    "indicators": legacy_macro_details.get("macro_indicators", []),
                    "auto_exec_indicators": legacy_macro_details.get("auto_exec_indicators", []),
                    "execution_indicators": legacy_macro_details.get("execution_indicators", []),
                    "network_indicators": legacy_macro_details.get("network_indicators", []),
                    "obfuscation_indicators": legacy_macro_details.get("obfuscation_indicators", []),
                    "external_reference_indicators": legacy_macro_details.get("external_reference_indicators", []),
                    "embedded_object_indicators": legacy_macro_details.get("embedded_object_indicators", []),
                    "limitations": legacy_macro_details.get("limitations", []),
                }

        macro_defense = self._build_macro_defense_result(
            filename=file.filename or "",
            detected_mime=detected_mime,
            zip_details=zip_details,
            legacy_details=legacy_macro_details,
            signature_mismatch_info=signature_mismatch_info,
            source_metadata=source_metadata,
        )
        macro_present = bool(macro_defense.macro_present)
        macro_suspicious = bool(macro_defense.macro_risk_score >= 0.75)
        malware_scan_details["macro_defense"] = macro_defense.model_dump()
        if macro_defense.macro_present or macro_defense.macro_risk_score > 0:
            existing_macro = malware_scan_details.get("macro") if isinstance(malware_scan_details.get("macro"), dict) else {}
            existing_macro.update({
                "present": bool(macro_defense.macro_present),
                "risky": bool(macro_defense.macro_risk_score >= 0.75),
                "risk_score": macro_defense.macro_risk_score,
                "risk_level": macro_defense.macro_risk_level,
                "container_type": macro_defense.macro_container_type,
                "indicators": macro_defense.macro_indicators,
                "auto_exec_indicators": macro_defense.auto_exec_indicators,
                "execution_indicators": macro_defense.execution_indicators,
                "network_indicators": macro_defense.network_indicators,
                "obfuscation_indicators": macro_defense.obfuscation_indicators,
                "external_reference_indicators": macro_defense.external_reference_indicators,
                "embedded_object_indicators": macro_defense.embedded_object_indicators,
                "recommended_handling": macro_defense.recommended_handling,
                "evidence_reasons": macro_defense.evidence_reasons,
                "limitations": macro_defense.limitations,
            })
            malware_scan_details["macro"] = existing_macro

        # Lightweight exec-marker heuristics (PowerShell/netcat/bash reverse shell) and JS skimmer/credential signals
        dangerous_exec = False
        exec_markers: List[str] = []
        skimmer_indicators: Dict[str, Any] = {"domains": [], "keywords": []}
        credsteal_indicators: List[str] = []
        try:
            text_lower = "" if is_oversize_upload else (file_content or b"").decode('utf-8', errors='ignore').lower()
            ps_exec = ('powershell' in text_lower) and (
                'iex' in text_lower or 'invoke-expression' in text_lower or 'downloadstring' in text_lower or 'system.net.webclient' in text_lower or ' -enc' in text_lower
            )
            ps_web_request = ('powershell' in text_lower) and (
                'invoke-webrequest' in text_lower or 'invoke-restmethod' in text_lower or ' iwr ' in text_lower or ' irm ' in text_lower
            )
            ps_obfuscation = ('powershell' in text_lower) and (
                '-encodedcommand' in text_lower or ' -enc ' in text_lower or 'frombase64string' in text_lower or ' hidden' in text_lower or ' bypass' in text_lower
            )
            ps_socket_shell = (
                ('system.net.sockets.tcplistener' in text_lower or 'system.net.sockets.tcpclient' in text_lower) and
                ('accepttcpclient' in text_lower or '.connect(' in text_lower) and
                'getstream' in text_lower and
                ('iex' in text_lower or 'invoke-expression' in text_lower)
            )
            ps_socket_listener = (
                ('powershell' in text_lower or 'new-object' in text_lower)
                and (
                    'system.net.sockets.tcplistener' in text_lower
                    or 'system.net.sockets.tcpclient' in text_lower
                    or 'new-object net.sockets.tcpclient' in text_lower
                )
            )
            nc_exec = (' nc ' in text_lower or text_lower.startswith('nc ') or '\nnc ' in text_lower) and (
                '/bin/sh -i' in text_lower or ' -e ' in text_lower or ' -c ' in text_lower or '|/bin/sh' in text_lower
            )
            sh_exec = ('bash -i' in text_lower) or ('/bin/sh -i' in text_lower)
            download_exec_chain = bool(
                re.search(
                    r"(?is)\b(?:curl|wget)\b[^\r\n]{0,220}(?:\||&&|;)\s*(?:bash|sh|zsh|powershell(?:\.exe)?|cmd(?:\.exe)?)\b",
                    text_lower,
                )
            )
            decoded_eval_chain = bool(
                re.search(
                    r"(?is)\beval\s*\([^)]*(?:atob\s*\(|fromcharcode\s*\(|base64_decode\s*\(|frombase64string)",
                    text_lower,
                )
                or ('eval(' in text_lower and ('atob(' in text_lower or 'base64' in text_lower))
            )
            script_eval_exec_combo = (
                'eval(' in text_lower
                and (
                    bool(re.search(r"(?i)\b(?:system|shell_exec|exec|passthru|popen|proc_open|os\.system)\b", text_lower))
                    or 'powershell' in text_lower
                )
            )
            eval_script_tag = ('<script' in text_lower and 'eval(' in text_lower)
            stacked_exec_keywords = (
                ('execution' in text_lower)
                and sum(
                    1
                    for token in ('powershell', 'php', 'js', 'eval(', 'base64', 'curl', 'wget')
                    if token in text_lower
                ) >= 2
            )
            if ps_exec:
                exec_markers.append('powershell_download_exec')
            if ps_web_request:
                exec_markers.append('powershell_web_request')
            if ps_obfuscation:
                exec_markers.append('powershell_obfuscation')
            if ps_socket_listener:
                exec_markers.append('powershell_socket_listener')
            if ps_socket_shell:
                exec_markers.append('powershell_socket_shell')
            if nc_exec:
                exec_markers.append('netcat_reverse_shell')
            if sh_exec:
                exec_markers.append('shell_reverse')
            if download_exec_chain:
                exec_markers.append('download_execute_chain')
            if decoded_eval_chain:
                exec_markers.append('decoded_eval_chain')
            if script_eval_exec_combo:
                exec_markers.append('script_eval_exec_combo')
            if eval_script_tag:
                exec_markers.append('eval_script_tag')
            if stacked_exec_keywords:
                exec_markers.append('stacked_execution_keywords')
            dangerous_exec = any(marker in HARD_EXEC_MARKERS for marker in exec_markers)

            # Skimmer: payment field keywords + exfil to non-allowed domain via fetch/xhr
            sk_kw = ['credit card', 'card number', 'cardnumber', 'cc', 'cvc', 'cvv', 'expiry', 'exp-date', 'pan', 'billing']
            matched_kw = [k for k in sk_kw if k in text_lower]
            # Extract domains referenced in JS network calls
            import re as _re
            domains = _re.findall(r"https?://([a-z0-9.-]+)", text_lower)
            suspicious_domains = []
            for d in domains:
                dlow = d.strip().lower()
                if not dlow:
                    continue
                if any(dlow.endswith(ad) for ad in (ALLOWED_PAYMENT_DOMAINS | ALLOWED_EXFIL_DOMAINS)):
                    continue
                # Only treat as suspicious if used with fetch/xhr/beacon and keywords
                if ('fetch(' in text_lower or 'xmlhttprequest' in text_lower or 'navigator.sendbeacon' in text_lower) and matched_kw:
                    suspicious_domains.append(dlow)
            if matched_kw and suspicious_domains:
                skimmer_indicators['domains'] = suspicious_domains
                skimmer_indicators['keywords'] = matched_kw

            # Credential stealer indicators
            if ('document.cookie' in text_lower):
                credsteal_indicators.append('document.cookie')
            if ('localstorage' in text_lower and ('getitem' in text_lower or 'setitem' in text_lower)):
                credsteal_indicators.append('localStorage access')
            if ('navigator.credentials' in text_lower):
                credsteal_indicators.append('navigator.credentials')
            if ('wp-config.php' in text_lower or 'id_rsa' in text_lower or 'begin rsa private key' in text_lower):
                credsteal_indicators.append('sensitive_file_keyword')
        except Exception:
            pass
        if exec_markers:
            malware_scan_details["exec_markers"] = exec_markers
        if skimmer_indicators.get('domains'):
            malware_scan_details["web_skimmer"] = skimmer_indicators
        if credsteal_indicators:
            malware_scan_details["credential_stealer"] = credsteal_indicators

        # Build MalwareScanResult (PoC-aware policy)
        malware_scan_result = MalwareScanResult(
            scan_engine_version="YARA + optional ClamAV",
            is_malicious=(
                bool(dangerous_yara_rules) or
                (bool(poc_yara_rules) and dangerous_exec and POC_YARA_POLICY in ('malicious_on_danger', 'block_on_danger')) or
                (clam.get('available') and clam.get('infected'))
            ),
            threat_name=(
                (dangerous_yara_rules[0] if dangerous_yara_rules else (outer_yara_rules[0] if outer_yara_rules else None))
                if outer_yara_rules else (clam.get('signature') if clam.get('infected') else None)
            ),
            scan_details=malware_scan_details or None,
        )

        # Extension/content mismatch heuristic (code disguised as another type)
        ext_mismatch = bool(signature_mismatch_info)
        mismatch_reason: Optional[str] = (
            str(signature_mismatch_info.get("reason"))
            if isinstance(signature_mismatch_info, dict) and signature_mismatch_info.get("reason")
            else None
        )
        try:
            _, ext = os.path.splitext(file.filename or "")
            ext = (ext or "").lower()
            head = (file_content or b"")[:4096]

            # Language markers
            php_markers = [b"<?php", b"<?=", b"<?"]
            html_markers = [b"<html", b"<!doctype html", b"<head", b"<body"]
            py_markers = [b"import requests", b"import urllib", b"urllib.request", b"http.cookiejar", b"def ", b"class "]
            sh_markers = [b"#!/bin/bash", b"#!/usr/bin/env bash", b"/bin/sh -i"]

            has_php = any(m in head.lower() for m in [m.lower() for m in php_markers])
            has_html = any(m in head.lower() for m in [m.lower() for m in html_markers])
            has_py = any(m in head for m in py_markers)
            has_sh = any(m in head for m in sh_markers)

            # Suspicious cases:
            # - .php without PHP markers
            # - .html/.htm without HTML markers but with Python/shell indicators
            # - .txt with strong code + CVE/Exploit-DB context (handled by YARA too, but add heuristic)
            if ext == ".php" and not has_php:
                ext_mismatch = True
                mismatch_reason = mismatch_reason or f"Extension '.php' but no PHP markers found in first 4KB; detected MIME '{detected_mime}'."
            elif ext in (".html", ".htm") and (not has_html) and (has_py or has_sh):
                ext_mismatch = True
                mismatch_reason = mismatch_reason or "Extension '.html' but contains script code indicators (Python/shell) and lacks HTML markers."
            elif ext in (".txt", ".md") and (has_py or has_sh):
                # Only treat as suspicious if there are also PoC cues in text to reduce false positives
                low = head.lower()
                if b"cve-" in low or b"exploit database" in low or b"edb-id:" in low or b"exploit-title:" in low:
                    ext_mismatch = True
                    mismatch_reason = mismatch_reason or f"Extension '{ext}' but contains exploit/script code indicators (PoC context)."
        except Exception:
            pass

        ml_scan_payload = None
        poc_text_hit = False
        if is_oversize_upload and detected_mime in TEXT_BASED_MIME_TYPES_FOR_ML:
            malware_scan_details["ml_skip_reason"] = "file_size_limit"
        elif detected_mime in TEXT_BASED_MIME_TYPES_FOR_ML and self._ml_model and file_content:
            try:
                text_content = file_content.decode('utf-8', errors='ignore')
                clf_name = None
                vec_name = None
                top_tokens: List[str] = []
                evidence_terms: List[str] = []
                shap_top: List[Dict[str, Any]] = []
                shap_algo: Optional[str] = None
                try:
                    from sklearn.pipeline import Pipeline  # type: ignore
                    if hasattr(self._ml_model, 'named_steps'):
                        pipe = self._ml_model  # type: ignore
                        # Vectorizer details
                        if 'tfidf' in pipe.named_steps:
                            vec = pipe.named_steps['tfidf']
                            vec_name = vec.__class__.__name__
                            try:
                                X = vec.transform([text_content])
                                if hasattr(vec, 'get_feature_names_out'):
                                    names = vec.get_feature_names_out()
                                else:
                                    names = getattr(vec, 'get_feature_names', lambda: [])()
                                if names is not None and hasattr(X, 'tocoo'):
                                    coo = X.tocoo()
                                    pairs = list(zip(coo.col.tolist(), coo.data.tolist()))
                                    pairs.sort(key=lambda p: p[1], reverse=True)
                                    for idx, val in pairs[:10]:
                                        if 0 <= idx < len(names):
                                            tok = str(names[idx])
                                            if tok:
                                                top_tokens.append(tok)
                            except Exception:
                                pass
                        # Classifier details
                        if 'clf' in pipe.named_steps:
                            clf = pipe.named_steps['clf']
                            clf_name = clf.__class__.__name__
                except Exception:
                    pass

                pred = self._ml_model.predict([text_content])[0]
                probs = self._ml_model.predict_proba([text_content])[0]
                is_suspicious_ml = bool(pred == 1)
                # Collect simple evidence terms
                tl = text_content.lower()
                for term in [
                    'cve-', 'exploit', 'poc', 'proof of concept', 'eval(', 'base64', 'powershell', 'invoke-expression',
                    'downloadstring', 'system.net.webclient', 'bash -i', ' nc ', 'curl ', 'wget ', 'xmlhttprequest', 'fetch(',
                    'addresssanitizer:', 'stack-buffer-overflow', 'expected result:', 'actual result:', 'test script:'
                ]:
                    if term in tl and term not in evidence_terms:
                        evidence_terms.append(term.strip())

                # Simple write-up PoC indicator even without YARA: CVE-####-#### and ("exploit title" or "poc")
                try:
                    import re as _re2
                    if _re2.search(r"cve-\d{4}-\d{4,7}", tl):
                        if ('exploit title' in tl) or ('\npoc' in tl) or (' proof of concept' in tl):
                            poc_text_hit = True
                except Exception:
                    pass
                # Advisory write-up (no CVE) but ASAN section + structured headings
                try:
                    if ('addresssanitizer:' in tl) and (('actual result:' in tl) or ('expected result:' in tl) or ('test script:' in tl)):
                        poc_text_hit = True
                        malware_scan_details.setdefault('writeup', True)
                except Exception:
                    pass

                ml_scan_payload = MLScanResult(
                    model_name=getattr(self._ml_model, '__class__', type('x', (), {})).__name__,
                    classifier_name=clf_name,
                    vectorizer_name=vec_name,
                    is_suspicious_ml=is_suspicious_ml,
                    prediction_label_ml="Suspicious Text" if is_suspicious_ml else "Benign Text",
                    prediction_score_ml=float(probs[1]),
                    top_tokens=top_tokens or None,
                    evidence_terms=evidence_terms or None,
                    shap_algorithm=None,
                    shap_top_features=None,
                )
                # Add richer reasoning for ML
                try:
                    extra_ml_reasons: List[str] = []
                    extra_ml_reasons.append(f"ML model: {clf_name or 'unknown'} with TF-IDF features; probability={float(probs[1]):.2f}.")
                    if top_tokens:
                        extra_ml_reasons.append("Top tokens: " + ", ".join(top_tokens[:6]))
                    if evidence_terms:
                        extra_ml_reasons.append("Evidence terms: " + ", ".join(evidence_terms[:6]))
                    # Append later alongside other reasons
                    malware_scan_details.setdefault('ml_explanation', extra_ml_reasons)
                except Exception:
                    pass

                # Optional SHAP attributions (set FILE_ML_SHAP_ENABLE=true to enable)
                try:
                    import os as _os
                    if _os.getenv('FILE_ML_SHAP_ENABLE', 'false').strip().lower() in {"1","true","yes","y"} and vec_name and clf_name and 'named_steps' in dir(self._ml_model):
                        try:
                            import shap  # type: ignore
                            pipe = self._ml_model  # type: ignore
                            vec = pipe.named_steps.get('tfidf')
                            clf = pipe.named_steps.get('clf')
                            if vec is not None and clf is not None:
                                X = vec.transform([text_content])
                                names = []
                                try:
                                    names = list(vec.get_feature_names_out())
                                except Exception:
                                    try:
                                        names = list(vec.get_feature_names())  # type: ignore
                                    except Exception:
                                        names = []
                                if clf_name in ("RandomForestClassifier", "ExtraTreesClassifier", "GradientBoostingClassifier", "LGBMClassifier", "XGBClassifier"):
                                    shap_algo = 'TreeExplainer'
                                    Xd = X.toarray()
                                    expl = shap.TreeExplainer(clf)
                                    try:
                                        svs = expl.shap_values(Xd)
                                        # RandomForestClassifier returns list per class
                                        if isinstance(svs, list) and len(svs) > 1:
                                            sv = svs[1][0]
                                        elif isinstance(svs, list):
                                            sv = svs[0][0]
                                        else:
                                            sv = svs[0]
                                    except Exception:
                                        sv = None
                                else:
                                    shap_algo = 'LinearExplainer'
                                    try:
                                        expl = shap.LinearExplainer(clf, X, feature_perturbation="interventional")
                                        sv_all = expl.shap_values(X)
                                        sv = sv_all[0] if isinstance(sv_all, list) else sv_all[0]
                                    except Exception:
                                        sv = None
                                if sv is not None:
                                    # Pair features with SHAP values
                                    try:
                                        import numpy as _np
                                        arr = _np.array(sv).reshape(-1)
                                        # Select top contributors toward class 1
                                        idxs = _np.argsort(-_np.abs(arr))[:10]
                                        for idx in idxs:
                                            tok = names[idx] if names and 0 <= idx < len(names) else f"f{idx}"
                                            shap_top.append({"token": str(tok), "value": float(arr[idx])})
                                    except Exception:
                                        pass
                                if shap_top:
                                    ml_scan_payload.shap_algorithm = shap_algo
                                    ml_scan_payload.shap_top_features = shap_top
                                    # Add to reasoning
                                    try:
                                        txt = ", ".join([f"{t['token']}({t['value']:+.2f})" for t in shap_top[:6]])
                                        malware_scan_details.setdefault('ml_explanation', []).append(f"SHAP: {shap_algo} top features: {txt}")
                                    except Exception:
                                        pass
                        except Exception:
                            pass
                except Exception:
                    pass
            except Exception as e:
                logger.error(f"Error during ML scan for file {file.filename}: {e}")
                errors_encountered.append("ML scan failed.")

        # Count inner YARA matches for risk contribution
        inner_yara_count = sum(len(m.get("rules", []) or []) for m in (inner_yara_matches or []))
        overall_assessment = self._assess_risk(
            filesize_kb,
            is_allowed_type,
            detected_mime,
            malware_scan_result.is_malicious,
            malware_scan_result.threat_name,
            ml_scan_payload,
            macro_suspicious=macro_suspicious,
            pdf_suspicious=pdf_suspicious,
            inner_yara_count=inner_yara_count,
        )
        overall_assessment = self._apply_macro_defense_to_assessment(overall_assessment, macro_defense)
        # Policy-based PoC handling if overall status remained Safe
        try:
            is_passive_pdf_context = (
                detected_mime == "application/pdf"
                and (not pdf_suspicious)
                and (not dangerous_exec)
            )
            status_lower = (overall_assessment.overall_status or '').lower()
            if status_lower == 'safe' and (poc_yara_rules or poc_text_hit):
                if is_passive_pdf_context:
                    rs = list(overall_assessment.reasoning or [])
                    if poc_yara_rules:
                        rs.append("PoC YARA indicators found in passive PDF context (no active exploit actions detected).")
                    if poc_text_hit:
                        rs.append("Exploit write-up text indicators found in passive PDF context.")
                    overall_assessment.reasoning = rs
                elif dangerous_exec and POC_YARA_POLICY in ('malicious_on_danger', 'block_on_danger'):
                    overall_assessment.overall_status = "Malicious (Exploit PoC with dangerous markers)"
                    overall_assessment.risk_score = max(0.9, float(overall_assessment.risk_score or 0.0))
                    overall_assessment.recommended_action = "BLOCK_AND_QUARANTINE"
                    rs = list(overall_assessment.reasoning or [])
                    if poc_yara_rules:
                        rs.append(f"PoC YARA rules: {', '.join(poc_yara_rules[:5])}")
                    if poc_text_hit:
                        rs.append("Exploit write-up indicators found (CVE tag + PoC/Exploit Title)")
                    if exec_markers:
                        rs.append(f"Exec indicators: {', '.join(exec_markers[:5])}")
                    overall_assessment.reasoning = rs
                else:
                    overall_assessment.overall_status = "Suspicious (Exploit PoC indicators)"
                    overall_assessment.risk_score = max(0.7, float(overall_assessment.risk_score or 0.0))
                    overall_assessment.recommended_action = "FLAG_FOR_REVIEW"
                    rs = list(overall_assessment.reasoning or [])
                    if poc_yara_rules:
                        rs.append(f"PoC YARA rules: {', '.join(poc_yara_rules[:5])}")
                    if poc_text_hit:
                        rs.append("Exploit write-up indicators found (CVE tag + PoC/Exploit Title)")
                    if exec_markers:
                        rs.append(f"Exec indicators: {', '.join(exec_markers[:5])}")
                    overall_assessment.reasoning = rs
            if (overall_assessment.overall_status or '').lower() == 'safe' and suspicious_yara_rules:
                rs = list(overall_assessment.reasoning or [])
                if is_passive_pdf_context:
                    rs.append(
                        "Medium-confidence YARA matches observed in passive PDF context; no active PDF exploit actions detected."
                    )
                else:
                    overall_assessment.overall_status = "Suspicious (YARA Medium Confidence)"
                    overall_assessment.risk_score = max(0.72, float(overall_assessment.risk_score or 0.0))
                    overall_assessment.recommended_action = "FLAG_FOR_REVIEW"
                    rs.append(f"Medium-confidence YARA matches: {', '.join(suspicious_yara_rules[:5])}")
                overall_assessment.reasoning = rs
            if (overall_assessment.overall_status or '').lower() == 'safe' and exec_markers:
                rs = list(overall_assessment.reasoning or [])
                rs.append(f"Exec indicators: {', '.join(exec_markers[:5])}")
                if any(marker in REMOTE_SHELL_EXEC_MARKERS for marker in exec_markers):
                    overall_assessment.overall_status = "Malicious (Remote Shell Indicators)"
                    overall_assessment.risk_score = max(0.9, float(overall_assessment.risk_score or 0.0))
                    overall_assessment.recommended_action = "BLOCK_AND_QUARANTINE"
                elif any(marker in HARD_EXEC_MARKERS for marker in exec_markers):
                    overall_assessment.overall_status = "Suspicious (Command Execution Indicators)"
                    overall_assessment.risk_score = max(0.8, float(overall_assessment.risk_score or 0.0))
                    overall_assessment.recommended_action = "FLAG_FOR_REVIEW_BLOCK"
                else:
                    overall_assessment.overall_status = "Suspicious (Script Execution Indicators)"
                    overall_assessment.risk_score = max(0.72, float(overall_assessment.risk_score or 0.0))
                    overall_assessment.recommended_action = "FLAG_FOR_REVIEW"
                overall_assessment.reasoning = rs
            # Web skimmer bump
            if (overall_assessment.overall_status or '').lower() == 'safe' and malware_scan_details.get('web_skimmer'):
                overall_assessment.overall_status = "Suspicious (Web Skimmer Indicators)"
                overall_assessment.risk_score = max(0.8, float(overall_assessment.risk_score or 0.0))
                overall_assessment.recommended_action = "FLAG_FOR_REVIEW_BLOCK"
                rs = list(overall_assessment.reasoning or [])
                ws = malware_scan_details.get('web_skimmer') or {}
                rs.append(f"Skimmer keywords: {', '.join((ws.get('keywords') or [])[:5])}")
                rs.append(f"Exfil domains: {', '.join((ws.get('domains') or [])[:5])}")
                overall_assessment.reasoning = rs
            # Credential-stealer bump
            if (overall_assessment.overall_status or '').lower() == 'safe' and malware_scan_details.get('credential_stealer'):
                overall_assessment.overall_status = "Suspicious (Credential Stealer Indicators)"
                overall_assessment.risk_score = max(0.75, float(overall_assessment.risk_score or 0.0))
                overall_assessment.recommended_action = "FLAG_FOR_REVIEW"
                rs = list(overall_assessment.reasoning or [])
                rs.append("Credential-stealer indicators present")
                overall_assessment.reasoning = rs
            # Archive policy indicators that do not require a signature hit.
            if (overall_assessment.overall_status or '').lower() == 'safe' and archive_suspicious:
                overall_assessment.overall_status = "Suspicious (Archive Risk Indicators)"
                overall_assessment.risk_score = max(0.78, float(overall_assessment.risk_score or 0.0))
                overall_assessment.recommended_action = "FLAG_FOR_REVIEW_BLOCK"
                rs = list(overall_assessment.reasoning or [])
                archive_info = malware_scan_details.get("archive") or {}
                reasons = [str(x) for x in (archive_info.get("suspicious_reasons") or []) if str(x)]
                entries = [str(x) for x in (archive_info.get("suspicious_entries") or []) if str(x)]
                if reasons:
                    rs.append(f"Archive risk indicators: {', '.join(reasons[:5])}")
                if entries:
                    rs.append(f"Archive entries: {', '.join(entries[:5])}")
                overall_assessment.reasoning = rs
        except Exception:
            pass
        # If otherwise safe, but extension/content mismatch is present, mark as Suspicious
        try:
            if ext_mismatch and (overall_assessment.overall_status or "").lower() == "safe":
                if dangerous_file_signature:
                    sig_kind = str(((signature_mismatch_info or {}).get("signature") or {}).get("kind") or "")
                    if sig_kind in EXECUTABLE_SIGNATURE_TYPES:
                        overall_assessment.overall_status = "Malicious (Executable Content Disguised)"
                        overall_assessment.risk_score = max(0.92, float(overall_assessment.risk_score or 0.0))
                        overall_assessment.recommended_action = "BLOCK_AND_QUARANTINE"
                    else:
                        overall_assessment.overall_status = "Suspicious (Disguised Script Content)"
                        overall_assessment.risk_score = max(0.82, float(overall_assessment.risk_score or 0.0))
                        overall_assessment.recommended_action = "FLAG_FOR_REVIEW_BLOCK"
                else:
                    overall_assessment.overall_status = "Suspicious (Extension/Content Mismatch)"
                    overall_assessment.risk_score = max(0.7, float(overall_assessment.risk_score or 0.0))
                    overall_assessment.recommended_action = "FLAG_FOR_REVIEW"
                reasons = list(overall_assessment.reasoning or [])
                if mismatch_reason:
                    reasons.append(mismatch_reason)
                else:
                    reasons.append("File extension does not match content/type.")
                overall_assessment.reasoning = reasons
        except Exception:
            pass
        # Enrich reasoning with specific indicators for better UX
        try:
            extra_reasons: List[str] = []
            if inner_yara_matches:
                for m in inner_yara_matches[:5]:  # cap to avoid very long lists
                    for r in (m.get("rules") or [])[:3]:
                        extra_reasons.append(f"YARA match inside archive: {m.get('path','?')} -> {r}")
            if macro_suspicious and (not malware_scan_result.is_malicious):
                macro_info = malware_scan_details.get("macro") or {}
                indicators = [str(x) for x in (macro_info.get("indicators") or []) if str(x)]
                if indicators:
                    extra_reasons.append(f"Risky macro indicators: {', '.join(indicators[:6])}")
                else:
                    extra_reasons.append("Risky macro indicators detected")
            elif macro_present and not macro_suspicious:
                extra_reasons.append("Macro container present without shell/network/obfuscation indicators.")
            if ext_mismatch and mismatch_reason:
                extra_reasons.append(mismatch_reason)
            if archive_suspicious:
                archive_info = malware_scan_details.get("archive") or {}
                reasons = [str(x) for x in (archive_info.get("suspicious_reasons") or []) if str(x)]
                if reasons:
                    extra_reasons.append(f"Archive risk indicators: {', '.join(reasons[:5])}")
            if pdf_suspicious:
                if pdf_hits:
                    extra_reasons.append(f"PDF suspicious keywords: {', '.join(pdf_hits[:5])}")
                else:
                    extra_reasons.append("PDF suspicious actions detected")
            # Include ML explanation details if present
            try:
                for r in (malware_scan_details.get('ml_explanation') or [])[:3]:
                    extra_reasons.append(r)
            except Exception:
                pass
            if extra_reasons:
                existing = list(overall_assessment.reasoning or [])
                overall_assessment.reasoning = existing + extra_reasons
        except Exception:
            pass

        status_lower = (overall_assessment.overall_status or '').lower()
        rec_action = (overall_assessment.recommended_action or '').upper()
        should_alert = (
            'malicious' in status_lower or
            'suspicious' in status_lower or
            rec_action.startswith('BLOCK') or
            rec_action.startswith('FLAG')
        )

        # Build optional text highlights for preview rendering on the client
        highlights: List[Dict[str, Any]] = []
        try:
            if detected_mime in TEXT_BASED_MIME_TYPES_FOR_ML and file_content and not is_oversize_upload:
                text_content = file_content.decode('utf-8', errors='ignore')
                tl = text_content.lower()
                def add_ranges(term: str, label: str, severity: str = 'medium', cap: int = 10):
                    nonlocal highlights
                    start = 0
                    term_l = term.lower()
                    cnt = 0
                    while True:
                        idx = tl.find(term_l, start)
                        if idx == -1:
                            break
                        end = idx + len(term_l)
                        highlights.append({
                            'start': idx,
                            'end': end,
                            'label': label,
                            'severity': severity,
                        })
                        cnt += 1
                        if cnt >= cap:
                            break
                        start = end
                # Highlight evidence terms
                for term in (ml_scan_payload.evidence_terms if ml_scan_payload and ml_scan_payload.evidence_terms else []):
                    add_ranges(term, f"evidence:{term}")
                # Highlight top tokens
                for tok in (ml_scan_payload.top_tokens if ml_scan_payload and ml_scan_payload.top_tokens else []):
                    if tok and len(tok) >= 3:
                        add_ranges(tok, f"token:{tok}", 'low')
                # Highlight PoC write-up cues
                if poc_text_hit:
                    add_ranges('cve-', 'CVE reference', 'medium')
                    add_ranges('exploit title', 'Exploit Title', 'low')
                    add_ranges('poc', 'PoC', 'low')
        except Exception:
            pass

        # --- Explainable AI (XAI) payload ---
        try:
            decision = (overall_assessment.recommended_action or "").upper() or ("BLOCK_UPLOAD" if should_alert else "ALLOW")
            severity = "High" if ("malicious" in status_lower or decision.startswith("BLOCK")) else ("Medium" if should_alert else "Low")
            evidence: List[XAIExplanationEvidence] = []
            attributions: List[Dict[str, Any]] = []
            trace: List[XAIExplanationTraceStep] = []

            if type_validation_result and type_validation_result.detected_mime_type:
                trace.append(
                    XAIExplanationTraceStep(
                        stage="type_validation",
                        summary=f"mime={type_validation_result.detected_mime_type} allowed={type_validation_result.is_allowed_type}",
                        details=type_validation_result.model_dump() if hasattr(type_validation_result, "model_dump") else None,
                    )
                )
                if type_validation_result.is_allowed_type is False:
                    evidence.append(
                        XAIExplanationEvidence(
                            id="disallowed_file_type",
                            label="Disallowed file type",
                            severity="high",
                            description="File type is not in the allowed list for uploads.",
                            snippet=str(type_validation_result.detected_mime_type),
                            source="type_validation",
                            impact="Higher likelihood of exploit payloads or unsafe formats.",
                        )
                    )
                if signature_mismatch_info:
                    evidence.append(
                        XAIExplanationEvidence(
                            id="extension_signature_mismatch",
                            label="Extension/content mismatch",
                            severity="high" if bool(signature_mismatch_info.get("dangerous_signature")) else "medium",
                            description="Declared extension does not match the detected content signature.",
                            snippet=str(signature_mismatch_info.get("reason") or ""),
                            source="type_validation",
                            impact="Common delivery pattern for disguised scripts, executables, or unsafe payloads.",
                        )
                    )

            if malware_scan_result:
                trace.append(
                    XAIExplanationTraceStep(
                        stage="signature_scan",
                        summary=f"yara_malicious={bool(malware_scan_result.is_malicious)} threat={malware_scan_result.threat_name or 'none'}",
                        details=malware_scan_result.model_dump() if hasattr(malware_scan_result, "model_dump") else None,
                    )
                )
                if bool(malware_scan_result.is_malicious):
                    matches: List[str] = []
                    sd = malware_scan_result.scan_details or {}
                    outer = sd.get("outer_yara_matches") or []
                    inner = sd.get("inner_yara_matches") or []
                    try:
                        if isinstance(outer, list):
                            matches.extend([str(x) for x in outer if x])
                        if isinstance(inner, list):
                            for item in inner:
                                if isinstance(item, dict) and isinstance(item.get("rules"), list):
                                    matches.extend([str(x) for x in item.get("rules") if x])
                    except Exception:
                        pass
                    snippet = ", ".join(matches[:8]) if matches else (malware_scan_result.threat_name or "")
                    evidence.append(
                        XAIExplanationEvidence(
                            id="yara_match",
                            label="YARA signature matched",
                            severity="high",
                            description="A known malicious or suspicious signature matched this file.",
                            snippet=snippet or None,
                            source="yara",
                            impact="Potential malware/webshell/exploit content.",
                        )
                    )
                sd = malware_scan_result.scan_details or {}
                macro_info = sd.get("macro") if isinstance(sd, dict) else None
                if isinstance(macro_info, dict) and bool(macro_info.get("risky")):
                    evidence.append(
                        XAIExplanationEvidence(
                            id="risky_macro",
                            label="Risky macro behavior",
                            severity="high" if macro_defense and macro_defense.macro_risk_level in {"high", "critical"} else "medium",
                            description="Static macro defence found macro execution, network, external-reference, or obfuscation indicators.",
                            snippet=", ".join([str(x) for x in (macro_info.get("indicators") or [])[:8]]) or None,
                            source="macro_defense",
                            impact="Macro-enabled documents can execute commands when opened.",
                        )
                    )
                if macro_defense is not None and (macro_defense.macro_present or macro_defense.macro_risk_score > 0):
                    evidence.append(
                        XAIExplanationEvidence(
                            id="macro_defense_result",
                            label=(
                                "Critical macro behaviour detected"
                                if macro_defense.macro_risk_level == "critical"
                                else "Risky macro detected"
                                if macro_defense.macro_risk_level == "high"
                                else "Macro defence finding"
                            ),
                            severity=(
                                "critical"
                                if macro_defense.macro_risk_level == "critical"
                                else "high"
                                if macro_defense.macro_risk_level == "high"
                                else "medium"
                                if macro_defense.macro_risk_level == "medium"
                                else "low"
                            ),
                            description="The file scanner performed static Office macro-container and risky macro-indicator analysis.",
                            snippet="; ".join(list(macro_defense.evidence_reasons or [])[:6]) or None,
                            source="macro_defense",
                            impact="Macros, external templates, OLE/ActiveX, or DDE indicators can enable malicious code execution or payload retrieval.",
                        )
                    )
                archive_info = sd.get("archive") if isinstance(sd, dict) else None
                if isinstance(archive_info, dict) and bool(archive_info.get("suspicious")):
                    evidence.append(
                        XAIExplanationEvidence(
                            id="archive_policy_indicators",
                            label="Archive risk indicators",
                            severity="medium",
                            description="Archive contains risky entry names, unsafe paths, encryption, or compression indicators.",
                            snippet=", ".join([str(x) for x in (archive_info.get("suspicious_reasons") or [])[:8]]) or None,
                            source="archive_scan",
                            impact="Attackers often hide payloads or evade scanning in nested or suspicious archives.",
                        )
                    )

            if ml_scan_payload:
                trace.append(
                    XAIExplanationTraceStep(
                        stage="ml_scan",
                        summary=f"suspicious={bool(ml_scan_payload.is_suspicious_ml)} label={ml_scan_payload.prediction_label_ml or 'n/a'} score={ml_scan_payload.prediction_score_ml}",
                        details=ml_scan_payload.model_dump() if hasattr(ml_scan_payload, "model_dump") else None,
                    )
                )
                if bool(getattr(ml_scan_payload, "is_suspicious_ml", False)):
                    evidence.append(
                        XAIExplanationEvidence(
                            id="ml_suspicious",
                            label="ML model flagged suspicious content",
                            severity="medium",
                            description="Content-based ML model indicates potentially malicious text or indicators.",
                            snippet=f"{ml_scan_payload.prediction_label_ml} (p={ml_scan_payload.prediction_score_ml})",
                            source="ml",
                            impact="Potential exploit/write-up/webshell markers within the file.",
                        )
                    )
                if getattr(ml_scan_payload, "evidence_terms", None):
                    evidence.append(
                        XAIExplanationEvidence(
                            id="evidence_terms",
                            label="Suspicious terms detected",
                            severity="low",
                            description="Matched suspicious terms inside extracted text content.",
                            snippet=", ".join(list(ml_scan_payload.evidence_terms or [])[:10]),
                            source="ml",
                        )
                    )
                if getattr(ml_scan_payload, "shap_top_features", None):
                    # Pass through SHAP attributions when available.
                    try:
                        if isinstance(ml_scan_payload.shap_top_features, list):
                            attributions = list(ml_scan_payload.shap_top_features)[:15]
                            if ml_scan_payload.shap_algorithm:
                                attributions = [{"algorithm": ml_scan_payload.shap_algorithm}] + attributions
                    except Exception:
                        pass

            trace.append(
                XAIExplanationTraceStep(
                    stage="aggregator",
                    summary=f"{overall_assessment.overall_status} -> {overall_assessment.recommended_action}",
                    details=overall_assessment.model_dump() if hasattr(overall_assessment, "model_dump") else None,
                )
            )

            remediation: List[str] = []
            if severity in {"High", "Medium"}:
                remediation.append("Block Request or Quarantine Request according to configured policy; do not claim completed durable quarantine unless enforcement is connected.")
                remediation.append("Allow only whitelisted MIME types and enforce size limits.")
                remediation.append("Scan archives recursively with depth and size limits to prevent hidden payloads.")
                if macro_defense and macro_defense.macro_risk_level in {"high", "critical"}:
                    remediation.append("Preserve evidence and submit for sandbox analysis if a dynamic-analysis provider is available.")
            else:
                remediation.append("Allow upload; continue monitoring and keep signatures/models up to date.")

            risk_score = self._risk_score_value(overall_assessment)
            decision_confidence = None
            confidence_label = None
            uncertainty_score = None
            uncertainty_components = None

            # Lightweight explanation fidelity based on signal agreement with final action.
            decision_is_restrictive = not decision.startswith("ALLOW")
            signal_total = 0
            signal_support = 0
            if type_validation_result is not None:
                signal_total += 1
                if bool(type_validation_result.is_allowed_type is False) == decision_is_restrictive:
                    signal_support += 1
            if malware_scan_result is not None:
                signal_total += 1
                if bool(malware_scan_result.is_malicious) == decision_is_restrictive:
                    signal_support += 1
            if ml_scan_payload is not None:
                signal_total += 1
                if bool(getattr(ml_scan_payload, "is_suspicious_ml", False)) == decision_is_restrictive:
                    signal_support += 1
            if macro_defense is not None and (macro_defense.macro_present or macro_defense.macro_risk_score > 0):
                signal_total += 1
                macro_restrictive = float(macro_defense.macro_risk_score or 0.0) >= 0.45
                if macro_restrictive == decision_is_restrictive:
                    signal_support += 1
            fidelity_score = round(signal_support / signal_total, 4) if signal_total > 0 else None

            # Approximate OOD risk from MIME ambiguity and low-confidence model outcomes.
            ood_raw = 0.0
            mime_lower = str(detected_mime or "").lower()
            if mime_lower in {"application/octet-stream", "binary/octet-stream"}:
                ood_raw += 0.45
            if type_validation_result and type_validation_result.is_allowed_type is False:
                ood_raw += 0.30
            if ml_scan_payload and isinstance(ml_scan_payload.prediction_score_ml, (int, float)):
                ml_score = float(ml_scan_payload.prediction_score_ml)
                if 0.40 <= ml_score <= 0.60:
                    ood_raw += 0.20
            if not ml_scan_payload and mime_lower in TEXT_BASED_MIME_TYPES_FOR_ML:
                ood_raw += 0.20
            ood_score = round(max(0.0, min(1.0, ood_raw)), 4)
            abstain_reason = None
            if ood_score >= 0.75 and severity != "High":
                abstain_reason = "HIGH_OOD_FILE_CONTENT_REVIEW_REQUIRED"
                remediation.append("Escalate to manual analyst review because file characteristics are out-of-distribution.")

            # overall_assessment.risk_score remains file threat risk. Decision
            # confidence is derived from the final allow/review/block action.
            if isinstance(risk_score, (int, float)):
                decision_confidence = self._decision_confidence_from_file_risk(
                    risk_score=risk_score,
                    recommended_action=decision,
                    overall_status=overall_assessment.overall_status,
                    ood_score=ood_score,
                )
                confidence_label = self._confidence_label(decision_confidence)
                threshold_distance = min(abs(float(risk_score) - 0.60), abs(float(risk_score) - 0.80))
                threshold_margin_uncertainty = 1.0 - min(threshold_distance / 0.20, 1.0)
                active_component_scores: List[float] = []
                if type_validation_result is not None:
                    active_component_scores.append(0.75 if type_validation_result.is_allowed_type is False else 0.05)
                if malware_scan_result is not None:
                    active_component_scores.append(1.0 if malware_scan_result.is_malicious else 0.0)
                if ml_scan_payload is not None and isinstance(ml_scan_payload.prediction_score_ml, (int, float)):
                    active_component_scores.append(max(0.0, min(1.0, float(ml_scan_payload.prediction_score_ml))))
                if macro_defense is not None and (macro_defense.macro_present or macro_defense.macro_risk_score > 0):
                    active_component_scores.append(max(0.0, min(1.0, float(macro_defense.macro_risk_score or 0.0))))
                static_disagreement_uncertainty = (
                    max(active_component_scores) - min(active_component_scores)
                    if len(active_component_scores) >= 2
                    else 0.0
                )
                missing_component_count = 0
                if ml_scan_payload is None:
                    missing_component_count += 1
                if malware_scan_result is None:
                    missing_component_count += 1
                missing_component_uncertainty = min(0.30, 0.10 * missing_component_count)
                low_fidelity_uncertainty = (
                    max(0.0, min(1.0, 1.0 - float(fidelity_score)))
                    if isinstance(fidelity_score, (int, float))
                    else 0.0
                )
                uncertainty_components = {
                    "threshold_margin_uncertainty": round(max(0.0, min(1.0, threshold_margin_uncertainty)), 4),
                    "static_signal_disagreement_uncertainty": round(max(0.0, min(1.0, static_disagreement_uncertainty)), 4),
                    "missing_component_uncertainty": round(missing_component_uncertainty, 4),
                    "ood_score": round(max(0.0, min(1.0, ood_score)), 4),
                    "low_fidelity_uncertainty": round(low_fidelity_uncertainty, 4),
                }
                uncertainty_score = round(max(uncertainty_components.values()), 4)

            model_bits: List[str] = []
            if ml_scan_payload and ml_scan_payload.model_name:
                model_bits.append(str(ml_scan_payload.model_name))
            elif self._ml_model is not None:
                model_bits.append(self._ml_model.__class__.__name__)
            if ml_scan_payload and ml_scan_payload.classifier_name:
                model_bits.append(str(ml_scan_payload.classifier_name))
            model_version = " + ".join(dict.fromkeys(model_bits)) if model_bits else None
            ruleset_version = (
                str(malware_scan_result.scan_engine_version)
                if (malware_scan_result and malware_scan_result.scan_engine_version)
                else "yara_ruleset_unknown"
            )
            policy_version = f"file_detection_policy:{POC_YARA_POLICY}"
            thresholds = {
                "size_mb_max": float(MAX_FILE_SIZE_MB),
                "archive_depth_max": float(MAX_ARCHIVE_DEPTH),
                "archive_files_max": float(MAX_ARCHIVE_FILES),
                "review_risk_min": 0.60,
                "block_risk_min": 0.80,
                "macro_high_risk_min": 0.80,
                "macro_critical_risk_min": 0.92,
            }
            caveats: List[str] = []
            if self._ml_model is None:
                caveats.append("ML content model unavailable; decision leans on signature/policy checks.")
            if not malware_scan_result:
                caveats.append("Signature scan details were unavailable for this sample.")
            if signal_total <= 1:
                caveats.append("Decision relied on limited signal families.")
            if macro_defense is not None:
                caveats.extend([str(x) for x in (macro_defense.limitations or []) if str(x)])

            explanation = XAIExplanation(
                decision=decision,
                severity=severity,
                threat_category="File upload scanning",
                risk_score=risk_score,
                decision_confidence=decision_confidence,
                confidence=decision_confidence,
                confidence_label=confidence_label,
                uncertainty_score=uncertainty_score,
                uncertainty_components=uncertainty_components,
                fidelity_score=fidelity_score,
                ood_score=ood_score,
                abstain_reason=abstain_reason,
                impact="Potential malware or exploit content in uploaded file." if severity in {"High", "Medium"} else "Low-risk file content.",
                evidence=evidence or None,
                highlights=highlights or None,
                model_attributions=attributions or None,
                decision_trace=trace or None,
                remediation=remediation or None,
                counterfactual="If no signatures matched and ML indicators were absent, the file would likely be classified Safe.",
                model_version=model_version,
                ruleset_version=ruleset_version,
                policy_version=policy_version,
                thresholds=thresholds,
                provenance={
                    "pipeline": "file_analysis_v2",
                    "signal_families": signal_total,
                    "supporting_signals": signal_support,
                    "uncertainty_components": uncertainty_components,
                    "macro_defense": macro_defense.model_dump(mode="json") if macro_defense is not None else None,
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                },
                caveats=caveats or None,
            )
        except Exception:
            explanation = None

        ai_reliability = None
        try:
            risk_for_reliability = self._risk_score_value(overall_assessment)
            decision_conf_for_reliability = (
                explanation.decision_confidence
                if explanation is not None and isinstance(explanation.decision_confidence, (int, float))
                else (
                    self._decision_confidence_from_file_risk(
                        risk_score=risk_for_reliability,
                        recommended_action=overall_assessment.recommended_action,
                        overall_status=overall_assessment.overall_status,
                    )
                    if isinstance(risk_for_reliability, (int, float))
                    else None
                )
            )
            reliability_rule_hits: List[str] = []
            reliability_rule_hits.extend([str(x) for x in dangerous_yara_rules or []])
            reliability_rule_hits.extend([str(x) for x in suspicious_yara_rules or []])
            reliability_rule_hits.extend([str(x) for x in poc_yara_rules or []])
            reliability_rule_hits.extend([str(x) for x in exec_markers or []])
            reliability_rule_hits.extend([str(x) for x in pdf_hits or []])
            if signature_mismatch_info:
                reliability_rule_hits.append("extension_content_mismatch")
            if macro_suspicious:
                reliability_rule_hits.append("macro_risky")
            if macro_defense and macro_defense.macro_risk_level in {"high", "critical"}:
                reliability_rule_hits.append(f"macro_defense_{macro_defense.macro_risk_level}")
            if archive_suspicious:
                reliability_rule_hits.append("archive_policy_indicator")
            if malware_scan_result and malware_scan_result.is_malicious:
                reliability_rule_hits.append("yara_signature_match")
            ai_reliability = assess_ai_reliability(
                domain="file",
                risk_score=risk_for_reliability,
                decision_confidence=decision_conf_for_reliability,
                uncertainty_score=explanation.uncertainty_score if explanation else 0.0,
                ood_score=explanation.ood_score if explanation else 0.0,
                fidelity_score=explanation.fidelity_score if explanation else 1.0,
                score_breakdown={
                    "yara_score": 1.0 if (dangerous_yara_rules or (malware_scan_result and malware_scan_result.is_malicious)) else (0.65 if suspicious_yara_rules else 0.0),
                    "ml_score": ml_scan_payload.prediction_score_ml if ml_scan_payload else None,
                    "ml_suspicious": bool(ml_scan_payload and ml_scan_payload.is_suspicious_ml),
                    "type_validation_allowed": bool(type_validation_result.is_allowed_type) if type_validation_result else None,
                    "extension_mismatch": bool(signature_mismatch_info),
                    "macro_risky": bool(macro_suspicious),
                    "macro_risk_score": macro_defense.macro_risk_score if macro_defense else None,
                    "macro_risk_level": macro_defense.macro_risk_level if macro_defense else None,
                    "archive_suspicious": bool(archive_suspicious),
                    "pdf_active": bool(pdf_suspicious),
                    "exec_marker_count": len(exec_markers or []),
                },
                final_action=overall_assessment.recommended_action,
                severity=explanation.severity if explanation else None,
                rule_hits=reliability_rule_hits,
                model_version=explanation.model_version if explanation else None,
                ruleset_version=explanation.ruleset_version if explanation else None,
            )
            if explanation is not None:
                explanation.ai_reliability = ai_reliability
        except Exception as e_rel:
            logger.error(f"AI reliability assessment failed for file analysis: {e_rel}", exc_info=True)

        structured_verdict = self._build_structured_verdict(
            analysis_id=analysis_id,
            filename=file.filename or "",
            file_content=file_content,
            type_validation_result=type_validation_result,
            malware_scan_result=malware_scan_result,
            ml_scan_payload=ml_scan_payload,
            overall_assessment=overall_assessment,
            dangerous_yara_rules=dangerous_yara_rules,
            suspicious_yara_rules=suspicious_yara_rules,
            poc_yara_rules=poc_yara_rules,
            inner_yara_matches=inner_yara_matches,
            macro_present=macro_present,
            pdf_suspicious=pdf_suspicious,
            pdf_hits=pdf_hits,
            exec_markers=exec_markers,
            ext_mismatch=ext_mismatch,
            mismatch_reason=mismatch_reason,
            malware_scan_details=malware_scan_details,
            macro_defense=macro_defense,
        )
        provider_status = self.get_dynamic_provider_status()
        provider_name = str(provider_status.get("active_provider") or getattr(self._dynamic_provider, "name", "none") or "none").strip().lower() or "none"
        file_profile = {
            "filesize_kb": round(filesize_kb, 4),
            "max_dynamic_size_mb": float(self._dynamic_policy_max_file_size_mb),
            "is_oversize": bool(filesize_kb > (float(self._dynamic_policy_max_file_size_mb) * 1024.0)),
            "is_allowed_type": bool(is_allowed_type),
            "detected_type": detected_mime,
            "declared_type": str(structured_verdict.declared_type or ""),
            "classification": str(structured_verdict.classification or "safe"),
            "score": float(structured_verdict.score) if isinstance(structured_verdict.score, (int, float)) else 0.0,
            "has_signature_hit": bool(structured_verdict.matched_rules or structured_verdict.matched_signatures),
            "has_archive_findings": bool(structured_verdict.archive_lineage or archive_suspicious),
            "has_macro": bool(macro_suspicious or (macro_defense and macro_defense.macro_present)),
            "has_exec_markers": bool(exec_markers),
            "has_pdf_active": bool(pdf_suspicious),
        }
        provider_context = {
            "dynamic_enabled": bool(self._dynamic_enabled),
            "provider_name": provider_name,
            "provider_available": bool(provider_status.get("available")),
            "policy_profile": self._dynamic_policy_profile,
            "risk_threshold": float(self._dynamic_policy_risk_threshold),
            "high_risk_mimes": sorted(self._dynamic_policy_high_risk_mimes),
            "exempt_exts": sorted(self._dynamic_policy_exempt_exts),
        }
        dynamic_policy_decision = self.decide_dynamic_analysis_request(
            static_verdict=structured_verdict,
            file_profile=file_profile,
            provider_context=provider_context,
        )
        dynamic_state = self._dynamic_state_from_policy_decision(
            provider_name=provider_name,
            decision=dynamic_policy_decision,
        )

        if bool(dynamic_policy_decision.get("requested")) and str(dynamic_policy_decision.get("request_decision") or "") == "request_dynamic":
            try:
                dynamic_state = await self._run_dynamic_analysis_stage(
                    analysis_id=analysis_id,
                    filename=file.filename or "",
                    file_content=file_content,
                    detected_mime=detected_mime,
                    overall_assessment=overall_assessment,
                )
                dynamic_state = self._apply_dynamic_policy_metadata(dynamic_state, dynamic_policy_decision)
            except Exception as e_dyn:
                dynamic_state = FileDynamicAnalysisState(
                    provider=provider_name,
                    submission_id=None,
                    dynamic_status="failed",
                    submitted_at=None,
                    completed_at=None,
                    failure_reason=f"dynamic_stage_error:{str(e_dyn)[:180]}",
                    dynamic_summary="Dynamic analysis stage failed unexpectedly.",
                    dynamic_evidence_items=[],
                    dynamic_iocs=[],
                )
                dynamic_state = self._apply_dynamic_policy_metadata(dynamic_state, dynamic_policy_decision)

        structured_verdict.dynamic_analysis = dynamic_state
        if dynamic_state.dynamic_iocs:
            structured_verdict.iocs = self._dedupe_iocs(list(structured_verdict.iocs or []) + list(dynamic_state.dynamic_iocs or []))
        if dynamic_state.dynamic_evidence_items:
            structured_verdict.evidence_items = list(structured_verdict.evidence_items or []) + list(dynamic_state.dynamic_evidence_items or [])

        dyn_stage_status = str(dynamic_state.dynamic_status or "not_requested")
        stage_state = "skipped"
        if dyn_stage_status in {"completed"}:
            stage_state = "hit" if (dynamic_state.dynamic_iocs or dynamic_state.dynamic_evidence_items) else "ok"
        elif dyn_stage_status in {"submitted", "running", "pending_submission"}:
            stage_state = dyn_stage_status
        elif dyn_stage_status in {"failed", "unavailable"}:
            stage_state = "error"
        structured_verdict.analysis_stages = list(structured_verdict.analysis_stages or []) + [
            FileVerdictStage(
                stage="dynamic_analysis",
                status=stage_state,
                summary=dynamic_state.dynamic_summary or f"status={dyn_stage_status}",
                details={
                    "provider": dynamic_state.provider,
                    "dynamic_status": dyn_stage_status,
                    "submission_id": dynamic_state.submission_id,
                    "failure_reason": dynamic_state.failure_reason,
                    "ioc_count": len(dynamic_state.dynamic_iocs or []),
                    "evidence_count": len(dynamic_state.dynamic_evidence_items or []),
                },
            )
        ]
        if dynamic_state.dynamic_status == "completed" and dynamic_state.dynamic_summary:
            structured_verdict.analyst_summary = (
                f"{structured_verdict.analyst_summary} Dynamic: {dynamic_state.dynamic_summary}"
            ).strip()
        elif dynamic_state.dynamic_status in {"failed", "unavailable"} and dynamic_state.failure_reason:
            structured_verdict.analyst_summary = (
                f"{structured_verdict.analyst_summary} Dynamic status: {dynamic_state.dynamic_status} ({dynamic_state.failure_reason})."
            ).strip()
        if explanation is not None:
            if dynamic_state.dynamic_status == "completed":
                dynamic_limitation = "Dynamic analysis completed and its provider evidence is included in the structured verdict."
            elif dynamic_state.requested:
                dynamic_limitation = (
                    "Dynamic analysis was requested by policy but did not complete in this scan response; "
                    "do not claim sandbox detonation from this explanation alone."
                )
            else:
                dynamic_limitation = "Dynamic sandboxing was not used for this file; static indicators and available ML/signature evidence drove the score."
            explanation = complete_explainability_contract(
                explanation,
                domain="file",
                input_summary=f"filename={file.filename or ''}, size_kb={filesize_kb:.2f}",
                limitations=[
                    dynamic_limitation,
                    "Quarantine wording is advisory unless the configured backend policy performs durable quarantine.",
                    *([str(x) for x in (macro_defense.limitations or []) if str(x)] if macro_defense is not None else []),
                ],
            ) or explanation

        verdict_bundle = _FilePureVerdictBundle(
            analysis_id=analysis_id,
            analysis_timestamp=analysis_timestamp,
            tenant_id=effective_tenant_id,
            filename=file.filename or "",
            filesize_kb=filesize_kb,
            type_validation_result=type_validation_result,
            malware_scan_result=malware_scan_result,
            ml_scan_payload=ml_scan_payload,
            overall_assessment=overall_assessment,
            structured_verdict=structured_verdict,
            explanation=explanation,
            highlights=highlights or None,
            errors_encountered=errors_encountered,
        )

        defender_actions, defender_action_summary = self._persist_emit_alerts_from_verdict(
            db=db,
            bundle=verdict_bundle,
        )

        return {
            "analysis_id": analysis_id,
            "analysis_timestamp": analysis_timestamp,
            "file_details": FileAnalysisDetails(
                filename=file.filename, filesize_kb=round(filesize_kb, 2),
                type_validation=type_validation_result, malware_scan=malware_scan_result, ml_scan=ml_scan_payload,
                macro_defense=macro_defense,
            ).model_dump(),
            "overall_assessment": overall_assessment.model_dump(),
            "structured_verdict": structured_verdict.model_dump(mode="json"),
            "errors": errors_encountered or None,
            "highlights": highlights or None,
            "macro_defense": macro_defense.model_dump(mode="json") if hasattr(macro_defense, "model_dump") else None,
            "explanation": explanation,
            "ai_reliability": ai_reliability,
            "defender_actions": defender_actions,
            "defender_action_summary": defender_action_summary,
        }
