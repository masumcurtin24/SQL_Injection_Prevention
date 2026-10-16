from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin
import base64
import hashlib
import os
import uuid
import httpx


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _safe_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _normalize_status(value: Any, *, default: str = "failed") -> str:
    token = str(value or "").strip().lower()
    mapping = {
        "queued": "submitted",
        "pending": "submitted",
        "submitted": "submitted",
        "processing": "running",
        "running": "running",
        "done": "completed",
        "complete": "completed",
        "completed": "completed",
        "error": "failed",
        "failed": "failed",
        "unavailable": "unavailable",
    }
    return mapping.get(token, default)


def _coerce_datetime(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except Exception:
        return None


def _as_dict_payload(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        if isinstance(value.get("data"), dict):
            return dict(value["data"])
        if isinstance(value.get("result"), dict):
            return dict(value["result"])
        return dict(value)
    return {}


class DynamicProviderError(RuntimeError):
    pass


class DynamicProviderUnavailable(DynamicProviderError):
    pass


@dataclass
class DynamicSubmissionHandle:
    provider: str
    submission_id: Optional[str]
    status: str
    submitted_at: Optional[datetime] = None
    message: Optional[str] = None


@dataclass
class DynamicStatusSnapshot:
    provider: str
    submission_id: str
    status: str
    updated_at: datetime
    failure_reason: Optional[str] = None


@dataclass
class DynamicEvidenceItem:
    code: str
    label: str
    severity: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    source_path: Optional[str] = None


@dataclass
class DynamicIOCItem:
    ioc_type: str
    value: str
    source_stage: str = "dynamic_analysis"
    source_path: Optional[str] = None
    confidence: Optional[float] = None
    severity_hint: Optional[str] = None


@dataclass
class DynamicResultPayload:
    provider: str
    submission_id: str
    status: str
    completed_at: Optional[datetime] = None
    summary: Optional[str] = None
    failure_reason: Optional[str] = None
    evidence_items: List[DynamicEvidenceItem] = field(default_factory=list)
    iocs: List[DynamicIOCItem] = field(default_factory=list)
    raw_provider_payload: Dict[str, Any] = field(default_factory=dict)


class BaseDynamicAnalysisProvider(ABC):
    name: str = "base"

    @abstractmethod
    async def submit(self, *, sample_ref: str, sample_bytes: bytes, metadata: Dict[str, Any]) -> DynamicSubmissionHandle:
        raise NotImplementedError

    @abstractmethod
    async def get_status(self, submission_id: str) -> DynamicStatusSnapshot:
        raise NotImplementedError

    @abstractmethod
    async def fetch_result(self, submission_id: str) -> DynamicResultPayload:
        raise NotImplementedError

    def diagnostics(self) -> Dict[str, Any]:
        return {
            "provider": self.name,
            "configured": True,
            "available": True,
            "reason": None,
        }


class NoOpDynamicAnalysisProvider(BaseDynamicAnalysisProvider):
    name = "none"

    def __init__(self, *, reason: str = "provider_not_configured") -> None:
        self._reason = str(reason or "provider_not_configured").strip() or "provider_not_configured"

    async def submit(self, *, sample_ref: str, sample_bytes: bytes, metadata: Dict[str, Any]) -> DynamicSubmissionHandle:
        return DynamicSubmissionHandle(
            provider=self.name,
            submission_id=None,
            status="unavailable",
            submitted_at=None,
            message=self._reason,
        )

    async def get_status(self, submission_id: str) -> DynamicStatusSnapshot:
        return DynamicStatusSnapshot(
            provider=self.name,
            submission_id=submission_id,
            status="unavailable",
            updated_at=_utcnow(),
            failure_reason=self._reason,
        )

    async def fetch_result(self, submission_id: str) -> DynamicResultPayload:
        return DynamicResultPayload(
            provider=self.name,
            submission_id=submission_id,
            status="unavailable",
            completed_at=None,
            summary=self._reason,
            failure_reason=self._reason,
        )

    def diagnostics(self) -> Dict[str, Any]:
        return {
            "provider": self.name,
            "configured": False,
            "available": False,
            "reason": self._reason,
        }


class FakeDynamicAnalysisProvider(BaseDynamicAnalysisProvider):
    """In-memory fake provider for tests; does not execute untrusted samples."""

    name = "fake"

    def __init__(
        self,
        *,
        completion_polls: int = 1,
        fail: bool = False,
        failure_reason: str = "provider_failed",
        result_payload: Optional[DynamicResultPayload] = None,
    ) -> None:
        self._completion_polls = max(0, int(completion_polls))
        self._fail = bool(fail)
        self._failure_reason = str(failure_reason or "provider_failed")
        self._result_payload = result_payload
        self._submissions: Dict[str, Dict[str, Any]] = {}

    async def submit(self, *, sample_ref: str, sample_bytes: bytes, metadata: Dict[str, Any]) -> DynamicSubmissionHandle:
        submission_id = f"fake-{uuid.uuid4()}"
        self._submissions[submission_id] = {
            "sample_ref": sample_ref,
            "metadata": dict(metadata or {}),
            "submitted_at": _utcnow(),
            "poll_count": 0,
        }
        return DynamicSubmissionHandle(
            provider=self.name,
            submission_id=submission_id,
            status="submitted",
            submitted_at=self._submissions[submission_id]["submitted_at"],
        )

    async def get_status(self, submission_id: str) -> DynamicStatusSnapshot:
        row = self._submissions.get(submission_id)
        if row is None:
            return DynamicStatusSnapshot(
                provider=self.name,
                submission_id=submission_id,
                status="failed",
                updated_at=_utcnow(),
                failure_reason="unknown_submission_id",
            )
        row["poll_count"] = int(row.get("poll_count") or 0) + 1
        polls = int(row["poll_count"])
        if self._fail and polls >= max(1, self._completion_polls):
            return DynamicStatusSnapshot(
                provider=self.name,
                submission_id=submission_id,
                status="failed",
                updated_at=_utcnow(),
                failure_reason=self._failure_reason,
            )
        if polls == 1:
            return DynamicStatusSnapshot(
                provider=self.name,
                submission_id=submission_id,
                status="submitted",
                updated_at=_utcnow(),
            )
        if polls <= self._completion_polls:
            return DynamicStatusSnapshot(
                provider=self.name,
                submission_id=submission_id,
                status="running",
                updated_at=_utcnow(),
            )
        return DynamicStatusSnapshot(
            provider=self.name,
            submission_id=submission_id,
            status="completed",
            updated_at=_utcnow(),
        )

    async def fetch_result(self, submission_id: str) -> DynamicResultPayload:
        row = self._submissions.get(submission_id)
        if row is None:
            return DynamicResultPayload(
                provider=self.name,
                submission_id=submission_id,
                status="failed",
                completed_at=_utcnow(),
                summary="Unknown submission id.",
                failure_reason="unknown_submission_id",
            )
        if self._fail:
            return DynamicResultPayload(
                provider=self.name,
                submission_id=submission_id,
                status="failed",
                completed_at=_utcnow(),
                summary="Fake provider failure.",
                failure_reason=self._failure_reason,
            )
        if self._result_payload is not None:
            payload = replace(self._result_payload)
            payload.provider = self.name
            payload.submission_id = submission_id
            payload.status = "completed"
            payload.completed_at = payload.completed_at or _utcnow()
            return payload
        return DynamicResultPayload(
            provider=self.name,
            submission_id=submission_id,
            status="completed",
            completed_at=_utcnow(),
            summary="Fake provider completed dynamic analysis.",
            evidence_items=[
                DynamicEvidenceItem(
                    code="sandbox_network_contact",
                    label="Network contact observed in sandbox report",
                    severity="medium",
                    details={"network_contact_count": 1},
                )
            ],
            iocs=[
                DynamicIOCItem(
                    ioc_type="domain",
                    value="dynamic-fake.example",
                    source_stage="dynamic_analysis",
                    confidence=0.8,
                    severity_hint="medium",
                )
            ],
        )

    def diagnostics(self) -> Dict[str, Any]:
        return {
            "provider": self.name,
            "configured": True,
            "available": True,
            "reason": None,
            "details": {
                "mode": "in_memory_fake",
                "completion_polls": self._completion_polls,
                "fail": self._fail,
            },
        }


class HttpDynamicAnalysisProvider(BaseDynamicAnalysisProvider):
    """External HTTP provider adapter; never executes samples locally."""

    name = "http"

    def __init__(
        self,
        *,
        base_url: str,
        api_key: Optional[str] = None,
        submit_path: str = "/v1/dynamic/submit",
        status_path_template: str = "/v1/dynamic/status/{submission_id}",
        result_path_template: str = "/v1/dynamic/result/{submission_id}",
        timeout_seconds: float = 10.0,
        verify_tls: bool = True,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        self._base_url = str(base_url or "").strip().rstrip("/")
        self._api_key = str(api_key or "").strip() or None
        self._submit_path = str(submit_path or "/v1/dynamic/submit").strip()
        self._status_path_template = str(status_path_template or "/v1/dynamic/status/{submission_id}").strip()
        self._result_path_template = str(result_path_template or "/v1/dynamic/result/{submission_id}").strip()
        self._timeout_seconds = max(1.0, _safe_float(timeout_seconds, 10.0))
        self._verify_tls = bool(verify_tls)
        self._transport = transport
        self._configured, self._config_reason = self._validate_config()

    def _validate_config(self) -> tuple[bool, Optional[str]]:
        if not self._base_url:
            return False, "missing_http_base_url"
        if not (self._base_url.startswith("http://") or self._base_url.startswith("https://")):
            return False, "invalid_http_base_url_scheme"
        if "{submission_id}" not in self._status_path_template:
            return False, "status_path_missing_submission_id_placeholder"
        if "{submission_id}" not in self._result_path_template:
            return False, "result_path_missing_submission_id_placeholder"
        return True, None

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def _build_url(self, path: str) -> str:
        clean = str(path or "").strip()
        if clean.startswith("http://") or clean.startswith("https://"):
            return clean
        return urljoin(f"{self._base_url}/", clean.lstrip("/"))

    async def _request_json(
        self,
        *,
        method: str,
        path: str,
        json_payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not self._configured:
            raise DynamicProviderUnavailable(self._config_reason or "provider_misconfigured")
        timeout = httpx.Timeout(self._timeout_seconds)
        async with httpx.AsyncClient(
            timeout=timeout,
            verify=self._verify_tls,
            transport=self._transport,
            headers=self._headers(),
        ) as client:
            response = await client.request(method.upper(), self._build_url(path), json=json_payload)
        if response.status_code >= 500:
            raise DynamicProviderUnavailable(f"http_{response.status_code}")
        if response.status_code >= 400:
            return {"status": "failed", "failure_reason": f"http_{response.status_code}"}
        try:
            payload = response.json()
        except Exception:
            return {"status": "failed", "failure_reason": "invalid_json_response"}
        return _as_dict_payload(payload)

    async def submit(self, *, sample_ref: str, sample_bytes: bytes, metadata: Dict[str, Any]) -> DynamicSubmissionHandle:
        if not self._configured:
            return DynamicSubmissionHandle(
                provider=self.name,
                submission_id=None,
                status="unavailable",
                submitted_at=None,
                message=self._config_reason or "provider_misconfigured",
            )
        sample_sha256 = hashlib.sha256(sample_bytes or b"").hexdigest() if sample_bytes is not None else None
        payload = {
            "sample_ref": sample_ref,
            "metadata": dict(metadata or {}),
            "sample": {
                "filename": str((metadata or {}).get("filename") or sample_ref),
                "size_bytes": len(sample_bytes or b""),
                "sha256": sample_sha256,
                "content_base64": base64.b64encode(sample_bytes or b"").decode("ascii"),
            },
        }
        try:
            data = await self._request_json(method="POST", path=self._submit_path, json_payload=payload)
        except DynamicProviderUnavailable as exc:
            return DynamicSubmissionHandle(
                provider=self.name,
                submission_id=None,
                status="unavailable",
                submitted_at=None,
                message=str(exc),
            )
        except Exception as exc:
            return DynamicSubmissionHandle(
                provider=self.name,
                submission_id=None,
                status="unavailable",
                submitted_at=None,
                message=f"submit_error:{str(exc)[:180]}",
            )

        submission_id = str(data.get("submission_id") or data.get("id") or data.get("job_id") or "").strip() or None
        status = _normalize_status(data.get("status"), default="submitted")
        if not submission_id:
            return DynamicSubmissionHandle(
                provider=self.name,
                submission_id=None,
                status="failed",
                submitted_at=None,
                message=str(data.get("failure_reason") or "missing_submission_id"),
            )
        submitted_at = _coerce_datetime(data.get("submitted_at")) or _utcnow()
        return DynamicSubmissionHandle(
            provider=self.name,
            submission_id=submission_id,
            status=status,
            submitted_at=submitted_at,
            message=str(data.get("message") or "").strip() or None,
        )

    async def get_status(self, submission_id: str) -> DynamicStatusSnapshot:
        if not self._configured:
            return DynamicStatusSnapshot(
                provider=self.name,
                submission_id=submission_id,
                status="unavailable",
                updated_at=_utcnow(),
                failure_reason=self._config_reason or "provider_misconfigured",
            )
        path = self._status_path_template.replace("{submission_id}", str(submission_id))
        try:
            data = await self._request_json(method="GET", path=path, json_payload=None)
        except DynamicProviderUnavailable as exc:
            return DynamicStatusSnapshot(
                provider=self.name,
                submission_id=submission_id,
                status="unavailable",
                updated_at=_utcnow(),
                failure_reason=str(exc),
            )
        except Exception as exc:
            return DynamicStatusSnapshot(
                provider=self.name,
                submission_id=submission_id,
                status="failed",
                updated_at=_utcnow(),
                failure_reason=f"status_error:{str(exc)[:180]}",
            )
        status = _normalize_status(data.get("status"), default="failed")
        return DynamicStatusSnapshot(
            provider=self.name,
            submission_id=submission_id,
            status=status,
            updated_at=_coerce_datetime(data.get("updated_at")) or _utcnow(),
            failure_reason=str(data.get("failure_reason") or "").strip() or None,
        )

    @staticmethod
    def _normalize_evidence_items(raw_items: Any) -> List[DynamicEvidenceItem]:
        normalized: List[DynamicEvidenceItem] = []
        for row in list(raw_items or []):
            if not isinstance(row, dict):
                continue
            code = str(row.get("code") or row.get("type") or "provider_evidence").strip() or "provider_evidence"
            label = str(row.get("label") or row.get("title") or code).strip() or code
            severity = str(row.get("severity") or "").strip().lower() or None
            source_path = str(row.get("source_path") or row.get("path") or "").strip() or None
            details = row.get("details")
            if not isinstance(details, dict):
                details = {k: v for k, v in row.items() if k not in {"code", "type", "label", "title", "severity", "source_path", "path"}}
            normalized.append(
                DynamicEvidenceItem(
                    code=code,
                    label=label,
                    severity=severity,
                    details=dict(details or {}),
                    source_path=source_path,
                )
            )
        return normalized

    @staticmethod
    def _normalize_iocs(raw_items: Any) -> List[DynamicIOCItem]:
        normalized: List[DynamicIOCItem] = []
        for row in list(raw_items or []):
            if not isinstance(row, dict):
                continue
            ioc_type = str(row.get("ioc_type") or row.get("type") or "").strip().lower()
            value = str(row.get("value") or "").strip()
            if not ioc_type or not value:
                continue
            confidence = row.get("confidence")
            normalized.append(
                DynamicIOCItem(
                    ioc_type=ioc_type,
                    value=value,
                    source_stage=str(row.get("source_stage") or "dynamic_analysis").strip() or "dynamic_analysis",
                    source_path=str(row.get("source_path") or "").strip() or None,
                    confidence=_safe_float(confidence, 0.7) if confidence is not None else 0.7,
                    severity_hint=str(row.get("severity_hint") or "").strip().lower() or None,
                )
            )
        return normalized

    async def fetch_result(self, submission_id: str) -> DynamicResultPayload:
        if not self._configured:
            return DynamicResultPayload(
                provider=self.name,
                submission_id=submission_id,
                status="unavailable",
                completed_at=None,
                summary="provider_misconfigured",
                failure_reason=self._config_reason or "provider_misconfigured",
            )
        path = self._result_path_template.replace("{submission_id}", str(submission_id))
        try:
            data = await self._request_json(method="GET", path=path, json_payload=None)
        except DynamicProviderUnavailable as exc:
            return DynamicResultPayload(
                provider=self.name,
                submission_id=submission_id,
                status="unavailable",
                completed_at=None,
                summary="Dynamic provider unavailable.",
                failure_reason=str(exc),
            )
        except Exception as exc:
            return DynamicResultPayload(
                provider=self.name,
                submission_id=submission_id,
                status="failed",
                completed_at=_utcnow(),
                summary="Dynamic provider result retrieval failed.",
                failure_reason=f"result_error:{str(exc)[:180]}",
            )
        status = _normalize_status(data.get("status"), default="failed")
        return DynamicResultPayload(
            provider=self.name,
            submission_id=str(data.get("submission_id") or submission_id),
            status=status,
            completed_at=_coerce_datetime(data.get("completed_at")) or (_utcnow() if status in {"completed", "failed"} else None),
            summary=str(data.get("summary") or data.get("message") or "").strip() or None,
            failure_reason=str(data.get("failure_reason") or "").strip() or None,
            evidence_items=self._normalize_evidence_items(data.get("evidence_items") or data.get("evidence") or data.get("findings")),
            iocs=self._normalize_iocs(data.get("iocs")),
            raw_provider_payload=dict(data or {}),
        )

    def diagnostics(self) -> Dict[str, Any]:
        return {
            "provider": self.name,
            "configured": bool(self._configured),
            "available": bool(self._configured),
            "reason": self._config_reason,
            "details": {
                "base_url": self._base_url,
                "submit_path": self._submit_path,
                "status_path_template": self._status_path_template,
                "result_path_template": self._result_path_template,
                "timeout_seconds": self._timeout_seconds,
                "verify_tls": self._verify_tls,
                "api_key_set": bool(self._api_key),
            },
        }


def create_dynamic_analysis_provider(
    provider_name: Optional[str] = None,
    provider_config: Optional[Dict[str, Any]] = None,
) -> BaseDynamicAnalysisProvider:
    cfg = dict(provider_config or {})
    name = str(provider_name or "none").strip().lower()
    if name in {"", "none", "off", "disabled", "noop"}:
        return NoOpDynamicAnalysisProvider(reason=str(cfg.get("reason") or "provider_not_configured"))
    if name == "fake":
        completion_polls_raw = cfg.get("completion_polls")
        if completion_polls_raw is None:
            completion_polls_raw = cfg.get("fake_completion_polls")
        if completion_polls_raw is None:
            completion_polls_raw = os.getenv("FILE_DYNAMIC_FAKE_COMPLETION_POLLS", "1")
        completion_polls = int(completion_polls_raw or 1)

        fail_raw = cfg.get("fail") if "fail" in cfg else cfg.get("fake_fail")
        if fail_raw is None:
            fail_raw = os.getenv("FILE_DYNAMIC_FAKE_FAIL", "false")
        fail = str(fail_raw).strip().lower() in {"1", "true", "yes", "y"}

        failure_reason_raw = cfg.get("failure_reason")
        if failure_reason_raw is None:
            failure_reason_raw = cfg.get("fake_failure_reason")
        if failure_reason_raw is None:
            failure_reason_raw = os.getenv("FILE_DYNAMIC_FAKE_FAILURE_REASON", "provider_failed")
        failure_reason = str(failure_reason_raw)
        return FakeDynamicAnalysisProvider(
            completion_polls=completion_polls,
            fail=fail,
            failure_reason=failure_reason,
        )
    if name == "http":
        base_url = str(cfg.get("base_url") or os.getenv("FILE_DYNAMIC_HTTP_BASE_URL", "")).strip()
        api_key = str(cfg.get("api_key") or os.getenv("FILE_DYNAMIC_HTTP_API_KEY", "")).strip() or None
        submit_path = str(cfg.get("submit_path") or os.getenv("FILE_DYNAMIC_HTTP_SUBMIT_PATH", "/v1/dynamic/submit")).strip()
        status_path_template = str(
            cfg.get("status_path_template") or os.getenv("FILE_DYNAMIC_HTTP_STATUS_PATH_TEMPLATE", "/v1/dynamic/status/{submission_id}")
        ).strip()
        result_path_template = str(
            cfg.get("result_path_template") or os.getenv("FILE_DYNAMIC_HTTP_RESULT_PATH_TEMPLATE", "/v1/dynamic/result/{submission_id}")
        ).strip()
        timeout_raw = cfg.get("timeout_seconds")
        if timeout_raw is None:
            timeout_raw = os.getenv("FILE_DYNAMIC_HTTP_TIMEOUT_SECONDS", "10")
        timeout_seconds = _safe_float(timeout_raw, 10.0)

        verify_tls_raw = cfg["verify_tls"] if "verify_tls" in cfg else os.getenv("FILE_DYNAMIC_HTTP_VERIFY_TLS", "true")
        verify_tls = str(verify_tls_raw).strip().lower() in {"1", "true", "yes", "y", "on"}
        transport = cfg.get("transport")
        return HttpDynamicAnalysisProvider(
            base_url=base_url,
            api_key=api_key,
            submit_path=submit_path,
            status_path_template=status_path_template,
            result_path_template=result_path_template,
            timeout_seconds=timeout_seconds,
            verify_tls=verify_tls,
            transport=transport if isinstance(transport, httpx.AsyncBaseTransport) else None,
        )
    return NoOpDynamicAnalysisProvider(reason=f"unsupported_provider:{name}")
