from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from sqlalchemy import or_
from sqlalchemy.orm import Session

from backend.core.models import (
    Alert as AlertModel,
    AlertCaseLink as AlertCaseLinkModel,
    DEFAULT_TENANT_ID,
    FileAnalysisLog as FileAnalysisLogModel,
    SQLAnalysisLog as SQLAnalysisLogModel,
    SecurityCase as SecurityCaseModel,
    SecurityCaseNote as SecurityCaseNoteModel,
    SpamAnalysisLog as SpamAnalysisLogModel,
)
from backend.server.schemas.investigation import (
    CorrelationLevel,
    InvestigationCorrelationReason,
    InvestigationRelatedEntity,
    InvestigationRelatedEvent,
    InvestigationTimelineItem,
)
from backend.utils.logging_utils import setup_logger
from backend.utils.user_summary import build_user_summary_map

logger = setup_logger(__name__)

_ALLOWED_EVENT_TYPES = {
    "query",
    "file_scan",
    "spam_check",
    "alert",
    "case",
    "case_note",
    "case_alert_link",
}

_URL_HOST_RE = re.compile(r"(?i)\b(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?(?:[/?#]|$)")
_EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})\b")
_SQL_QUOTED_RE = re.compile(r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"")
_SQL_NUM_RE = re.compile(r"\b\d+(?:\.\d+)?\b")
_SQL_COMMENT_RE = re.compile(r"(--[^\n\r]*|/\*.*?\*/)", re.DOTALL)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _to_utc_datetime(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _safe_json_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _resolve_tenant_id(tenant_id: Optional[str]) -> str:
    normalized = str(tenant_id or "").strip()
    return normalized or DEFAULT_TENANT_ID


def _normalize_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip())


def _normalize_token(value: Any) -> str:
    return _normalize_text(value).lower()


def _safe_short_text(value: Any, *, max_len: int = 180) -> str:
    text = _normalize_text(value)
    if len(text) <= max_len:
        return text
    return f"{text[: max_len - 3]}..."


def _normalize_severity(value: Any, fallback: str = "Info") -> str:
    text = _normalize_text(value)
    return text or fallback


def _severity_for_file(category: Optional[str], status: Optional[str], action: Optional[str]) -> str:
    category_lc = _normalize_token(category)
    status_lc = _normalize_token(status)
    action_up = _normalize_text(action).upper()
    if (
        category_lc == "blocked"
        or "malicious" in status_lc
        or "unauthorized" in status_lc
        or action_up.startswith("BLOCK")
        or "QUARANTINE" in action_up
    ):
        return "High"
    if category_lc == "suspicious" or "suspicious" in status_lc:
        return "Medium"
    return "Low"


def _severity_for_spam(is_spam: bool, label: str, category: Optional[str]) -> str:
    label_lc = _normalize_token(label)
    category_lc = _normalize_token(category)
    if "phish" in label_lc or category_lc == "blocked":
        return "High"
    if is_spam or category_lc == "suspicious":
        return "Medium"
    return "Low"


def _extract_alert_analysis_id(alert_id: str) -> Optional[str]:
    normalized = _normalize_text(alert_id)
    if not normalized.startswith("alert-"):
        return None
    suffix = normalized[len("alert-") :].strip()
    return suffix or None


def _sql_fingerprint(query: Optional[str]) -> Optional[str]:
    text = _normalize_text(query)
    if not text:
        return None
    normalized = _SQL_COMMENT_RE.sub(" ", text)
    normalized = _SQL_QUOTED_RE.sub("?", normalized)
    normalized = _SQL_NUM_RE.sub("?", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip().lower()
    if not normalized:
        return None
    return hashlib.sha1(normalized.encode("utf-8")).hexdigest()[:16]


def _looks_like_hash(text: str) -> bool:
    value = _normalize_text(text).lower()
    if not value:
        return False
    if not re.fullmatch(r"[a-f0-9]{32,128}", value):
        return False
    return len(value) in {32, 40, 56, 64, 96, 128}


def _extract_first_hash(payload: Any) -> Optional[str]:
    if isinstance(payload, dict):
        for key, value in payload.items():
            key_lc = _normalize_token(key)
            if key_lc in {"sha256", "sha1", "md5", "file_hash", "hash", "digest"}:
                candidate = _normalize_token(value)
                if _looks_like_hash(candidate):
                    return candidate
            nested = _extract_first_hash(value)
            if nested:
                return nested
    elif isinstance(payload, list):
        for value in payload:
            nested = _extract_first_hash(value)
            if nested:
                return nested
    elif isinstance(payload, str):
        candidate = _normalize_token(payload)
        if _looks_like_hash(candidate):
            return candidate
    return None


def _extract_domain_from_email(value: Optional[str]) -> Optional[str]:
    text = _normalize_token(value)
    if not text:
        return None
    if "@" in text:
        domain = text.split("@", 1)[1].strip(".")
        if domain:
            return domain
    match = _EMAIL_RE.search(text)
    if match:
        return _normalize_token(match.group(1).strip("."))
    return None


def _extract_hosts(values: Iterable[Any]) -> List[str]:
    hosts: List[str] = []
    seen: set[str] = set()
    for raw in values:
        if raw is None:
            continue
        text = _normalize_text(raw)
        if not text:
            continue
        for match in _URL_HOST_RE.finditer(text):
            host = _normalize_token(match.group(1).strip("."))
            if not host or host in seen:
                continue
            seen.add(host)
            hosts.append(host)
            if len(hosts) >= 8:
                return hosts
    return hosts


def _safe_json_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    return []


def _extract_structured_file_iocs(details: Dict[str, Any]) -> List[Dict[str, Any]]:
    structured = _safe_json_dict(details.get("structured_verdict"))
    iocs = _safe_json_list(structured.get("iocs"))
    dynamic = _safe_json_dict(structured.get("dynamic_analysis"))
    dynamic_iocs = _safe_json_list(dynamic.get("dynamic_iocs"))
    combined = list(iocs) + list(dynamic_iocs)
    normalized: List[Dict[str, Any]] = []
    for item in combined:
        if not isinstance(item, dict):
            continue
        ioc_type = _normalize_token(item.get("type"))
        ioc_value = _normalize_text(item.get("value"))
        if not ioc_type or not ioc_value:
            continue
        normalized.append(
            {
                "type": ioc_type,
                "value": ioc_value,
                "source_stage": _normalize_text(item.get("source_stage")),
                "source_path": _normalize_text(item.get("source_path")),
                "dedup_key": _normalize_text(item.get("dedup_key")),
            }
        )
    return normalized


def _first_ioc_value(iocs: Sequence[Dict[str, Any]], ioc_type: str) -> Optional[str]:
    target = _normalize_token(ioc_type)
    for item in iocs:
        if _normalize_token(item.get("type")) != target:
            continue
        value = _normalize_text(item.get("value"))
        if value:
            return value
    return None


def _first_ioc_url_host(iocs: Sequence[Dict[str, Any]]) -> Optional[str]:
    for item in iocs:
        if _normalize_token(item.get("type")) != "url":
            continue
        value = _normalize_text(item.get("value"))
        if not value:
            continue
        hosts = _extract_hosts([value])
        if hosts:
            return _normalize_token(hosts[0])
    return None


def _parse_event_types_csv(value: Optional[str]) -> List[str]:
    if not value:
        return [
            "query",
            "file_scan",
            "spam_check",
            "alert",
            "case",
            "case_note",
            "case_alert_link",
        ]
    requested = [_normalize_token(token) for token in str(value).split(",")]
    filtered = [token for token in requested if token in _ALLOWED_EVENT_TYPES]
    if not filtered:
        return [
            "query",
            "file_scan",
            "spam_check",
            "alert",
            "case",
            "case_note",
            "case_alert_link",
        ]
    ordered: List[str] = []
    seen: set[str] = set()
    for token in filtered:
        if token in seen:
            continue
        seen.add(token)
        ordered.append(token)
    return ordered


def _apply_time_filters(
    query,
    column,
    *,
    start: Optional[datetime],
    end: Optional[datetime],
    before: Optional[datetime],
):
    start_utc = _to_utc_datetime(start)
    end_utc = _to_utc_datetime(end)
    before_utc = _to_utc_datetime(before)
    if before_utc is not None:
        if end_utc is None or before_utc < end_utc:
            end_utc = before_utc
    if start_utc is not None:
        query = query.filter(column >= start_utc)
    if end_utc is not None:
        query = query.filter(column < end_utc)
    return query


@dataclass
class _RawEvent:
    id: str
    tenant_id: str
    timestamp: datetime
    event_type: str
    severity: Optional[str]
    title: str
    summary: Optional[str]
    actor_user_id: Optional[str]
    owner_user_id: Optional[str]
    entity_keys: Dict[str, str] = field(default_factory=dict)
    source_ref: Dict[str, str] = field(default_factory=dict)
    case_ids: List[str] = field(default_factory=list)
    correlation_level: Optional[CorrelationLevel] = None
    correlation_reasons: List[InvestigationCorrelationReason] = field(default_factory=list)
    related_entities: List[InvestigationRelatedEntity] = field(default_factory=list)
    related_events: List[InvestigationRelatedEvent] = field(default_factory=list)


@dataclass
class _Reason:
    code: str
    label: str
    weight: int
    detail: Optional[str] = None
    key: Optional[str] = None
    value: Optional[str] = None


class InvestigationService:
    _instance: Optional["InvestigationService"] = None
    _initialized_flag: bool = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(InvestigationService, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if InvestigationService._initialized_flag:
            return
        logger.info("Initializing InvestigationService...")
        InvestigationService._initialized_flag = True
        logger.info("InvestigationService initialized successfully.")

    @classmethod
    def get_instance(cls) -> "InvestigationService":
        if not cls._initialized_flag or cls._instance is None:
            raise RuntimeError("InvestigationService is not initialized.")
        return cls._instance

    @classmethod
    def is_initialized(cls) -> bool:
        return bool(cls._initialized_flag)

    @staticmethod
    def _dedupe_preserve(values: Iterable[str]) -> List[str]:
        seen: set[str] = set()
        out: List[str] = []
        for raw in values:
            value = _normalize_text(raw)
            if not value or value in seen:
                continue
            seen.add(value)
            out.append(value)
        return out

    @staticmethod
    def _entity_set(entity_keys: Dict[str, str], *keys: str) -> set[str]:
        values: set[str] = set()
        for key in keys:
            text = _normalize_token(entity_keys.get(key))
            if text:
                values.add(text)
        return values

    @staticmethod
    def _event_sort_key(event: _RawEvent) -> Tuple[datetime, str]:
        return (_to_utc_datetime(event.timestamp) or datetime.min.replace(tzinfo=timezone.utc), event.id)

    def _fetch_alert_case_links(
        self,
        db: Session,
        *,
        tenant_id: str,
        alert_ids: Sequence[str],
        case_ids: Sequence[str],
    ) -> List[AlertCaseLinkModel]:
        query = db.query(AlertCaseLinkModel).filter(AlertCaseLinkModel.tenant_id == tenant_id)
        conditions = []
        if alert_ids:
            conditions.append(AlertCaseLinkModel.alert_id.in_(list(alert_ids)))
        if case_ids:
            conditions.append(AlertCaseLinkModel.case_id.in_(list(case_ids)))
        if conditions:
            query = query.filter(or_(*conditions))
        return query.order_by(AlertCaseLinkModel.linked_at.desc()).limit(5000).all()

    def _resolve_case_links(
        self,
        db: Session,
        *,
        tenant_id: str,
        query_ids: Sequence[str],
        file_ids: Sequence[str],
        spam_ids: Sequence[str],
        alert_ids: Sequence[str],
        case_ids_hint: Sequence[str],
    ) -> Tuple[Dict[str, List[str]], Dict[str, List[str]], Dict[str, Dict[str, Any]]]:
        source_case_map: Dict[str, List[str]] = {}
        case_meta: Dict[str, Dict[str, Any]] = {}

        source_type_candidates = {
            "query",
            "sql",
            "sql_query",
            "file",
            "file_scan",
            "upload",
            "spam",
            "spam_check",
            "email",
            "alert",
        }

        source_ids_for_lookup = self._dedupe_preserve(
            list(query_ids) + list(file_ids) + list(spam_ids) + list(alert_ids)
        )

        cases_query = db.query(
            SecurityCaseModel.id,
            SecurityCaseModel.owner_user_id,
            SecurityCaseModel.severity,
            SecurityCaseModel.status,
            SecurityCaseModel.source_type,
            SecurityCaseModel.source_id,
            SecurityCaseModel.created_by_user_id,
            SecurityCaseModel.title,
        ).filter(SecurityCaseModel.tenant_id == tenant_id)

        if source_ids_for_lookup:
            cases_query = cases_query.filter(
                or_(
                    SecurityCaseModel.id.in_(list(case_ids_hint) + source_ids_for_lookup),
                    SecurityCaseModel.source_id.in_(source_ids_for_lookup),
                    SecurityCaseModel.source_type.in_(list(source_type_candidates)),
                )
            )
        elif case_ids_hint:
            cases_query = cases_query.filter(SecurityCaseModel.id.in_(list(case_ids_hint)))

        for (
            case_id,
            owner_user_id,
            severity,
            status,
            source_type,
            source_id,
            created_by_user_id,
            title,
        ) in cases_query.all():
            case_id_text = _normalize_text(case_id)
            if not case_id_text:
                continue
            case_meta[case_id_text] = {
                "owner_user_id": _normalize_text(owner_user_id) or None,
                "severity": _normalize_text(severity) or None,
                "status": _normalize_text(status) or None,
                "source_type": _normalize_token(source_type) or None,
                "source_id": _normalize_text(source_id) or None,
                "created_by_user_id": _normalize_text(created_by_user_id) or None,
                "title": _normalize_text(title) or None,
            }
            source_type_norm = _normalize_token(source_type)
            source_id_norm = _normalize_text(source_id)
            if source_type_norm and source_id_norm:
                key = f"{source_type_norm}:{source_id_norm}"
                source_case_map.setdefault(key, [])
                source_case_map[key].append(case_id_text)

        for key, values in list(source_case_map.items()):
            source_case_map[key] = self._dedupe_preserve(values)

        derived_alert_ids = [f"alert-{value}" for value in self._dedupe_preserve(list(query_ids) + list(file_ids) + list(spam_ids))]
        all_alert_ids = self._dedupe_preserve(list(alert_ids) + derived_alert_ids)
        links = self._fetch_alert_case_links(
            db,
            tenant_id=tenant_id,
            alert_ids=all_alert_ids,
            case_ids=list(case_meta.keys()) + list(case_ids_hint),
        )

        alert_case_map: Dict[str, List[str]] = {}
        case_alert_map: Dict[str, List[str]] = {}
        for row in links:
            alert_id = _normalize_text(row.alert_id)
            case_id = _normalize_text(row.case_id)
            if not alert_id or not case_id:
                continue
            alert_case_map.setdefault(alert_id, [])
            alert_case_map[alert_id].append(case_id)
            case_alert_map.setdefault(case_id, [])
            case_alert_map[case_id].append(alert_id)

        for key in list(alert_case_map.keys()):
            alert_case_map[key] = self._dedupe_preserve(alert_case_map[key])
        for key in list(case_alert_map.keys()):
            case_alert_map[key] = self._dedupe_preserve(case_alert_map[key])

        for case_id, meta in case_meta.items():
            for alert_id in case_alert_map.get(case_id, []):
                source_key = f"alert:{alert_id}"
                source_case_map.setdefault(source_key, [])
                source_case_map[source_key].append(case_id)

            source_type_norm = _normalize_token(meta.get("source_type"))
            source_id_norm = _normalize_text(meta.get("source_id"))
            if source_type_norm and source_id_norm:
                source_key = f"{source_type_norm}:{source_id_norm}"
                source_case_map.setdefault(source_key, [])
                source_case_map[source_key].append(case_id)

        for key in list(source_case_map.keys()):
            source_case_map[key] = self._dedupe_preserve(source_case_map[key])

        return source_case_map, alert_case_map, case_meta

    def _resolve_case_ids_for_event(
        self,
        *,
        event_type: str,
        source_id: Optional[str],
        alert_id: Optional[str],
        analysis_id: Optional[str],
        source_case_map: Dict[str, List[str]],
        alert_case_map: Dict[str, List[str]],
    ) -> List[str]:
        keys: List[str] = []
        source = _normalize_text(source_id)
        alert = _normalize_text(alert_id)
        analysis = _normalize_text(analysis_id)

        if source:
            keys.append(f"{event_type}:{source}")
            if event_type == "query":
                keys.extend([f"sql:{source}", f"sql_query:{source}"])
            elif event_type == "file_scan":
                keys.extend([f"file:{source}", f"upload:{source}"])
            elif event_type == "spam_check":
                keys.extend([f"spam:{source}", f"email:{source}"])
            elif event_type == "alert":
                keys.append(f"alert:{source}")

        if alert:
            keys.append(f"alert:{alert}")

        if analysis:
            if analysis.startswith("sql-"):
                keys.extend([f"query:{analysis}", f"sql:{analysis}"])
            elif analysis.startswith("file-"):
                keys.extend([f"file_scan:{analysis}", f"file:{analysis}"])
            elif analysis.startswith("email-spam-"):
                keys.extend([f"spam_check:{analysis}", f"spam:{analysis}", f"email:{analysis}"])
            keys.append(f"alert:alert-{analysis}")

        case_ids: List[str] = []
        for key in keys:
            case_ids.extend(source_case_map.get(key, []))

        if event_type == "alert":
            if source:
                case_ids.extend(alert_case_map.get(source, []))
            if analysis:
                case_ids.extend(alert_case_map.get(f"alert-{analysis}", []))

        return self._dedupe_preserve(case_ids)

    def _build_query_events(
        self,
        db: Session,
        *,
        tenant_id: str,
        limit: int,
        start: Optional[datetime],
        end: Optional[datetime],
        before: Optional[datetime],
        source_case_map: Dict[str, List[str]],
        alert_case_map: Dict[str, List[str]],
        case_meta: Dict[str, Dict[str, Any]],
    ) -> List[_RawEvent]:
        query = db.query(SQLAnalysisLogModel).filter(SQLAnalysisLogModel.tenant_id == tenant_id)
        query = _apply_time_filters(query, SQLAnalysisLogModel.timestamp, start=start, end=end, before=before)
        rows = query.order_by(SQLAnalysisLogModel.timestamp.desc()).limit(limit).all()

        out: List[_RawEvent] = []
        for row in rows:
            analysis_id = _normalize_text(row.id)
            if not analysis_id:
                continue
            combined = _safe_json_dict(row.combined_assessment)
            validation = _safe_json_dict(row.query_validation_result)
            risk_level = _normalize_text(row.risk_level or combined.get("overall_risk_level"))
            action = _normalize_text(row.suggested_action or combined.get("suggested_action"))
            query_text = _normalize_text(row.query_received)
            fingerprint = _sql_fingerprint(query_text)

            service_name = None
            for key in ("service", "service_name", "application", "app", "source_service"):
                candidate = _normalize_text(combined.get(key))
                if candidate:
                    service_name = candidate
                    break

            case_ids = self._resolve_case_ids_for_event(
                event_type="query",
                source_id=analysis_id,
                alert_id=None,
                analysis_id=analysis_id,
                source_case_map=source_case_map,
                alert_case_map=alert_case_map,
            )

            owner_user_id = None
            for case_id in case_ids:
                owner_candidate = _normalize_text(case_meta.get(case_id, {}).get("owner_user_id"))
                if owner_candidate:
                    owner_user_id = owner_candidate
                    break

            entity_keys: Dict[str, str] = {"analysis_id": analysis_id}
            if fingerprint:
                entity_keys["query_fingerprint"] = fingerprint
            if service_name:
                entity_keys["service"] = _normalize_token(service_name)
            label = _normalize_text(validation.get("classification_label"))
            if label:
                entity_keys["classification_label"] = _normalize_token(label)

            out.append(
                _RawEvent(
                    id=f"query:{analysis_id}",
                    tenant_id=tenant_id,
                    timestamp=_to_utc_datetime(row.timestamp) or _utcnow(),
                    event_type="query",
                    severity=_normalize_severity(risk_level, "Info"),
                    title=f"SQL analysis: {_safe_short_text(query_text or analysis_id, max_len=120)}",
                    summary=_safe_short_text(
                        " | ".join(
                            [
                                f"Risk: {risk_level}" if risk_level else "",
                                f"Action: {action}" if action else "",
                                f"Classifier: {label}" if label else "",
                            ]
                        ).strip(" |"),
                        max_len=220,
                    )
                    or None,
                    actor_user_id=None,
                    owner_user_id=owner_user_id,
                    entity_keys=entity_keys,
                    source_ref={"type": "query", "id": analysis_id},
                    case_ids=case_ids,
                )
            )

        return out

    def _build_file_events(
        self,
        db: Session,
        *,
        tenant_id: str,
        limit: int,
        start: Optional[datetime],
        end: Optional[datetime],
        before: Optional[datetime],
        source_case_map: Dict[str, List[str]],
        alert_case_map: Dict[str, List[str]],
        case_meta: Dict[str, Dict[str, Any]],
    ) -> List[_RawEvent]:
        query = db.query(FileAnalysisLogModel).filter(FileAnalysisLogModel.tenant_id == tenant_id)
        query = _apply_time_filters(query, FileAnalysisLogModel.timestamp, start=start, end=end, before=before)
        rows = query.order_by(FileAnalysisLogModel.timestamp.desc()).limit(limit).all()

        out: List[_RawEvent] = []
        for row in rows:
            analysis_id = _normalize_text(row.id)
            if not analysis_id:
                continue
            details = _safe_json_dict(row.file_details)
            overall = _safe_json_dict(row.overall_assessment)
            filename = _normalize_text(row.filename or details.get("filename") or analysis_id)
            status = _normalize_text(row.overall_status or overall.get("overall_status"))
            action = _normalize_text(row.recommended_action or overall.get("recommended_action"))
            category = _normalize_text(row.category)
            risk_score = overall.get("risk_score")
            normalized_iocs = _extract_structured_file_iocs(details)

            type_validation = _safe_json_dict(details.get("type_validation"))
            mime_type = _normalize_text(type_validation.get("detected_mime_type"))
            file_hash = _normalize_token(_first_ioc_value(normalized_iocs, "hash")) or _extract_first_hash(details)
            url_host = _first_ioc_url_host(normalized_iocs)
            domain = _normalize_token(_first_ioc_value(normalized_iocs, "domain"))
            source_ip = _normalize_token(_first_ioc_value(normalized_iocs, "ip"))
            email_value = _normalize_token(_first_ioc_value(normalized_iocs, "email"))
            path_value = _normalize_token(_first_ioc_value(normalized_iocs, "path"))
            command_value = _normalize_token(_first_ioc_value(normalized_iocs, "command"))

            case_ids = self._resolve_case_ids_for_event(
                event_type="file_scan",
                source_id=analysis_id,
                alert_id=None,
                analysis_id=analysis_id,
                source_case_map=source_case_map,
                alert_case_map=alert_case_map,
            )
            owner_user_id = None
            for case_id in case_ids:
                owner_candidate = _normalize_text(case_meta.get(case_id, {}).get("owner_user_id"))
                if owner_candidate:
                    owner_user_id = owner_candidate
                    break

            entity_keys: Dict[str, str] = {
                "analysis_id": analysis_id,
                "filename": _normalize_token(filename),
            }
            if mime_type:
                entity_keys["mime_type"] = _normalize_token(mime_type)
            if file_hash:
                entity_keys["file_hash"] = _normalize_token(file_hash)
            if url_host:
                entity_keys["url_host"] = _normalize_token(url_host)
            if domain:
                entity_keys["domain"] = _normalize_token(domain)
            if source_ip:
                entity_keys["source_ip"] = _normalize_token(source_ip)
            if email_value:
                entity_keys["email"] = _normalize_token(email_value)
            if path_value:
                entity_keys["path"] = _normalize_token(path_value)
            if command_value:
                entity_keys["command"] = _normalize_token(command_value)

            summary_parts = [
                f"Status: {status}" if status else "",
                f"Action: {action}" if action else "",
                f"Risk: {risk_score}" if isinstance(risk_score, (int, float)) else "",
                f"IOC count: {len(normalized_iocs)}" if normalized_iocs else "",
            ]
            summary = _safe_short_text(" | ".join([part for part in summary_parts if part]), max_len=220) or None

            out.append(
                _RawEvent(
                    id=f"file_scan:{analysis_id}",
                    tenant_id=tenant_id,
                    timestamp=_to_utc_datetime(row.timestamp) or _utcnow(),
                    event_type="file_scan",
                    severity=_severity_for_file(category, status, action),
                    title=f"File scan: {_safe_short_text(filename, max_len=120)}",
                    summary=summary,
                    actor_user_id=None,
                    owner_user_id=owner_user_id,
                    entity_keys=entity_keys,
                    source_ref={"type": "file_scan", "id": analysis_id},
                    case_ids=case_ids,
                )
            )
        return out

    def _build_spam_events(
        self,
        db: Session,
        *,
        tenant_id: str,
        limit: int,
        start: Optional[datetime],
        end: Optional[datetime],
        before: Optional[datetime],
        source_case_map: Dict[str, List[str]],
        alert_case_map: Dict[str, List[str]],
        case_meta: Dict[str, Dict[str, Any]],
    ) -> List[_RawEvent]:
        query = db.query(SpamAnalysisLogModel).filter(SpamAnalysisLogModel.tenant_id == tenant_id)
        query = _apply_time_filters(query, SpamAnalysisLogModel.timestamp, start=start, end=end, before=before)
        rows = query.order_by(SpamAnalysisLogModel.timestamp.desc()).limit(limit).all()

        out: List[_RawEvent] = []
        for row in rows:
            analysis_id = _normalize_text(row.id)
            if not analysis_id:
                continue
            classification = _safe_json_dict(row.spam_classification_result)
            subject = _normalize_text(row.received_subject)
            label = _normalize_text(row.classification_label or classification.get("classification_label"))
            is_spam = bool(row.is_spam) or bool(classification.get("is_spam"))
            spam_score = row.spam_score if isinstance(row.spam_score, (int, float)) else classification.get("spam_score")
            category = _normalize_text(row.category)

            sender_domain = None
            for key in ("sender_domain", "from_domain", "domain"):
                candidate = _normalize_text(classification.get(key))
                if candidate:
                    sender_domain = _normalize_token(candidate)
                    break
            if sender_domain is None:
                for key in ("sender_email", "from_email", "email"):
                    sender_domain = _extract_domain_from_email(classification.get(key))
                    if sender_domain:
                        break
            if sender_domain is None:
                sender_domain = _extract_domain_from_email(subject)

            url_hosts = _extract_hosts(
                [
                    classification.get("url"),
                    classification.get("urls"),
                    classification.get("url_hosts"),
                    classification.get("suspicious_urls"),
                    subject,
                ]
            )

            case_ids = self._resolve_case_ids_for_event(
                event_type="spam_check",
                source_id=analysis_id,
                alert_id=None,
                analysis_id=analysis_id,
                source_case_map=source_case_map,
                alert_case_map=alert_case_map,
            )
            owner_user_id = None
            for case_id in case_ids:
                owner_candidate = _normalize_text(case_meta.get(case_id, {}).get("owner_user_id"))
                if owner_candidate:
                    owner_user_id = owner_candidate
                    break

            entity_keys: Dict[str, str] = {"analysis_id": analysis_id}
            if sender_domain:
                entity_keys["sender_domain"] = sender_domain
            if url_hosts:
                entity_keys["url_host"] = url_hosts[0]
            if label:
                entity_keys["classification_label"] = _normalize_token(label)

            summary_parts = [
                f"Label: {label}" if label else "",
                f"Spam score: {spam_score:.3f}" if isinstance(spam_score, (int, float)) else "",
                f"Sender domain: {sender_domain}" if sender_domain else "",
            ]
            summary = _safe_short_text(" | ".join([part for part in summary_parts if part]), max_len=220) or None

            out.append(
                _RawEvent(
                    id=f"spam_check:{analysis_id}",
                    tenant_id=tenant_id,
                    timestamp=_to_utc_datetime(row.timestamp) or _utcnow(),
                    event_type="spam_check",
                    severity=_severity_for_spam(is_spam, label, category),
                    title=f"Email analysis: {_safe_short_text(subject or label or analysis_id, max_len=120)}",
                    summary=summary,
                    actor_user_id=None,
                    owner_user_id=owner_user_id,
                    entity_keys=entity_keys,
                    source_ref={"type": "spam_check", "id": analysis_id},
                    case_ids=case_ids,
                )
            )
        return out

    def _build_alert_events(
        self,
        db: Session,
        *,
        tenant_id: str,
        limit: int,
        start: Optional[datetime],
        end: Optional[datetime],
        before: Optional[datetime],
        source_case_map: Dict[str, List[str]],
        alert_case_map: Dict[str, List[str]],
        case_meta: Dict[str, Dict[str, Any]],
    ) -> List[_RawEvent]:
        query = db.query(AlertModel).filter(AlertModel.tenant_id == tenant_id)
        query = _apply_time_filters(query, AlertModel.timestamp, start=start, end=end, before=before)
        rows = query.order_by(AlertModel.timestamp.desc()).limit(limit).all()

        out: List[_RawEvent] = []
        for row in rows:
            alert_id = _normalize_text(row.id)
            if not alert_id:
                continue
            analysis_id = _extract_alert_analysis_id(alert_id)
            query_fingerprint = _sql_fingerprint(row.query)

            case_ids = self._resolve_case_ids_for_event(
                event_type="alert",
                source_id=alert_id,
                alert_id=alert_id,
                analysis_id=analysis_id,
                source_case_map=source_case_map,
                alert_case_map=alert_case_map,
            )

            owner_user_id = None
            for case_id in case_ids:
                owner_candidate = _normalize_text(case_meta.get(case_id, {}).get("owner_user_id"))
                if owner_candidate:
                    owner_user_id = owner_candidate
                    break

            entity_keys: Dict[str, str] = {"alert_id": alert_id}
            if analysis_id:
                entity_keys["analysis_id"] = analysis_id
            if row.source_ip:
                entity_keys["source_ip"] = _normalize_token(row.source_ip)
            if row.target:
                target = _normalize_text(row.target)
                entity_keys["target"] = _normalize_token(target)
                entity_keys["service"] = _normalize_token(target)
            if query_fingerprint:
                entity_keys["query_fingerprint"] = query_fingerprint

            out.append(
                _RawEvent(
                    id=f"alert:{alert_id}",
                    tenant_id=tenant_id,
                    timestamp=_to_utc_datetime(row.timestamp) or _utcnow(),
                    event_type="alert",
                    severity=_normalize_severity(row.severity, "High"),
                    title=_safe_short_text(row.title or f"Alert {alert_id}", max_len=140),
                    summary=_safe_short_text(row.message, max_len=220) or None,
                    actor_user_id=None,
                    owner_user_id=owner_user_id,
                    entity_keys=entity_keys,
                    source_ref={"type": "alert", "id": alert_id},
                    case_ids=case_ids,
                )
            )
        return out

    def _build_case_events(
        self,
        db: Session,
        *,
        tenant_id: str,
        limit: int,
        start: Optional[datetime],
        end: Optional[datetime],
        before: Optional[datetime],
        source_case_map: Dict[str, List[str]],
        alert_case_map: Dict[str, List[str]],
        case_meta: Dict[str, Dict[str, Any]],
    ) -> List[_RawEvent]:
        query = db.query(SecurityCaseModel).filter(SecurityCaseModel.tenant_id == tenant_id)
        query = _apply_time_filters(query, SecurityCaseModel.updated_at, start=start, end=end, before=before)
        rows = query.order_by(SecurityCaseModel.updated_at.desc()).limit(limit).all()

        out: List[_RawEvent] = []
        for row in rows:
            case_id = _normalize_text(row.id)
            if not case_id:
                continue
            source_id = _normalize_text(row.source_id)
            source_type = _normalize_token(row.source_type)

            entity_keys: Dict[str, str] = {"case_id": case_id}
            if source_id:
                entity_keys["source_id"] = source_id
            if source_type:
                entity_keys["source_type"] = source_type
            if row.domain:
                entity_keys["domain"] = _normalize_token(row.domain)
            if row.owner_user_id:
                entity_keys["owner_user_id"] = _normalize_text(row.owner_user_id)
            if row.created_by_user_id:
                entity_keys["created_by_user_id"] = _normalize_text(row.created_by_user_id)

            linked_alerts = alert_case_map.get(case_id, [])
            if linked_alerts:
                entity_keys["alert_id"] = linked_alerts[0]

            out.append(
                _RawEvent(
                    id=f"case:{case_id}",
                    tenant_id=tenant_id,
                    timestamp=_to_utc_datetime(row.updated_at or row.created_at) or _utcnow(),
                    event_type="case",
                    severity=_normalize_severity(row.severity, "Medium"),
                    title=f"Case: {_safe_short_text(row.title or case_id, max_len=120)}",
                    summary=_safe_short_text(
                        f"Status: {_normalize_text(row.status)} | Source: {source_type or 'n/a'}:{source_id or 'n/a'}",
                        max_len=220,
                    ),
                    actor_user_id=_normalize_text(row.created_by_user_id) or None,
                    owner_user_id=_normalize_text(row.owner_user_id) or None,
                    entity_keys=entity_keys,
                    source_ref={"type": "case", "id": case_id},
                    case_ids=[case_id],
                )
            )

        return out

    def _build_case_note_events(
        self,
        db: Session,
        *,
        tenant_id: str,
        limit: int,
        start: Optional[datetime],
        end: Optional[datetime],
        before: Optional[datetime],
        case_meta: Dict[str, Dict[str, Any]],
        alert_case_map: Dict[str, List[str]],
    ) -> List[_RawEvent]:
        query = db.query(SecurityCaseNoteModel).filter(SecurityCaseNoteModel.tenant_id == tenant_id)
        query = _apply_time_filters(query, SecurityCaseNoteModel.created_at, start=start, end=end, before=before)
        rows = query.order_by(SecurityCaseNoteModel.created_at.desc()).limit(limit).all()

        out: List[_RawEvent] = []
        for row in rows:
            note_id = _normalize_text(row.id)
            case_id = _normalize_text(row.case_id)
            if not note_id or not case_id:
                continue
            meta = case_meta.get(case_id, {})
            entity_keys: Dict[str, str] = {
                "note_id": note_id,
                "case_id": case_id,
            }
            author_id = _normalize_text(row.author_user_id)
            if author_id:
                entity_keys["author_user_id"] = author_id
            source_id = _normalize_text(meta.get("source_id"))
            source_type = _normalize_token(meta.get("source_type"))
            if source_id:
                entity_keys["source_id"] = source_id
            if source_type:
                entity_keys["source_type"] = source_type
            alert_ids = alert_case_map.get(case_id, [])
            if alert_ids:
                entity_keys["alert_id"] = alert_ids[0]

            out.append(
                _RawEvent(
                    id=f"case_note:{note_id}",
                    tenant_id=tenant_id,
                    timestamp=_to_utc_datetime(row.created_at) or _utcnow(),
                    event_type="case_note",
                    severity=_normalize_severity(meta.get("severity"), "Info"),
                    title=f"Case note: {case_id}",
                    summary=_safe_short_text(row.note, max_len=220) or None,
                    actor_user_id=author_id or None,
                    owner_user_id=_normalize_text(meta.get("owner_user_id")) or None,
                    entity_keys=entity_keys,
                    source_ref={"type": "case_note", "id": note_id, "case_id": case_id},
                    case_ids=[case_id],
                )
            )
        return out

    def _build_case_alert_link_events(
        self,
        db: Session,
        *,
        tenant_id: str,
        limit: int,
        start: Optional[datetime],
        end: Optional[datetime],
        before: Optional[datetime],
        case_meta: Dict[str, Dict[str, Any]],
    ) -> List[_RawEvent]:
        query = db.query(AlertCaseLinkModel).filter(AlertCaseLinkModel.tenant_id == tenant_id)
        query = _apply_time_filters(query, AlertCaseLinkModel.linked_at, start=start, end=end, before=before)
        rows = query.order_by(AlertCaseLinkModel.linked_at.desc()).limit(limit).all()

        out: List[_RawEvent] = []
        for row in rows:
            link_id = _normalize_text(row.id)
            case_id = _normalize_text(row.case_id)
            alert_id = _normalize_text(row.alert_id)
            if not link_id or not case_id or not alert_id:
                continue
            analysis_id = _extract_alert_analysis_id(alert_id)
            meta = case_meta.get(case_id, {})
            entity_keys: Dict[str, str] = {
                "link_id": link_id,
                "case_id": case_id,
                "alert_id": alert_id,
            }
            if analysis_id:
                entity_keys["analysis_id"] = analysis_id
            if row.linked_by_user_id:
                entity_keys["linked_by_user_id"] = _normalize_text(row.linked_by_user_id)

            source_id = _normalize_text(meta.get("source_id"))
            source_type = _normalize_token(meta.get("source_type"))
            if source_id:
                entity_keys["source_id"] = source_id
            if source_type:
                entity_keys["source_type"] = source_type

            out.append(
                _RawEvent(
                    id=f"case_alert_link:{link_id}",
                    tenant_id=tenant_id,
                    timestamp=_to_utc_datetime(row.linked_at) or _utcnow(),
                    event_type="case_alert_link",
                    severity=_normalize_severity(meta.get("severity"), "Info"),
                    title=f"Alert linked to case: {case_id}",
                    summary=_safe_short_text(
                        row.note or f"Linked alert {alert_id} to case {case_id}",
                        max_len=220,
                    ),
                    actor_user_id=_normalize_text(row.linked_by_user_id) or None,
                    owner_user_id=_normalize_text(meta.get("owner_user_id")) or None,
                    entity_keys=entity_keys,
                    source_ref={"type": "case_alert_link", "id": link_id, "case_id": case_id, "alert_id": alert_id},
                    case_ids=[case_id],
                )
            )
        return out

    def _event_matches_entity_filter(
        self,
        event: _RawEvent,
        *,
        entity_key: Optional[str],
        entity_value: Optional[str],
    ) -> bool:
        key = _normalize_text(entity_key)
        value = _normalize_token(entity_value)
        if not key and not value:
            return True

        if key:
            event_value = _normalize_token(event.entity_keys.get(key))
            if not event_value:
                return False
            if not value:
                return True
            return value == event_value or value in event_value

        for raw in event.entity_keys.values():
            event_value = _normalize_token(raw)
            if not event_value:
                continue
            if value == event_value or value in event_value:
                return True
        return False

    @staticmethod
    def _reason_to_schema(reason: _Reason) -> InvestigationCorrelationReason:
        return InvestigationCorrelationReason(
            code=reason.code,
            label=reason.label,
            detail=reason.detail,
            key=reason.key,
            value=reason.value,
        )

    @staticmethod
    def _pair_level(total_weight: int) -> CorrelationLevel:
        if total_weight >= 9:
            return "strong"
        if total_weight >= 5:
            return "moderate"
        if total_weight >= 2:
            return "weak"
        return "none"

    def _pair_reasons(self, left: _RawEvent, right: _RawEvent) -> List[_Reason]:
        reasons: List[_Reason] = []
        non_time_reasons: List[_Reason] = []

        shared_case_ids = sorted(set(left.case_ids).intersection(right.case_ids))
        if shared_case_ids:
            case_id = shared_case_ids[0]
            base_weight = 4 if ("alert" in {left.event_type, right.event_type}) else 3
            non_time_reasons.append(
                _Reason(
                    code="same_case_id",
                    label="same case id",
                    weight=base_weight,
                    key="case_id",
                    value=case_id,
                )
            )

        left_alert = _normalize_text(left.entity_keys.get("alert_id"))
        right_alert = _normalize_text(right.entity_keys.get("alert_id"))
        if left_alert and right_alert and left_alert == right_alert:
            non_time_reasons.append(
                _Reason(
                    code="same_alert_id",
                    label="same alert id",
                    weight=4,
                    key="alert_id",
                    value=left_alert,
                )
            )

        if "case_alert_link" in {left.event_type, right.event_type} and (left_alert or right_alert):
            link_alert = left_alert if left.event_type == "case_alert_link" else right_alert
            if link_alert:
                non_time_reasons.append(
                    _Reason(
                        code="alert_case_link",
                        label="matched by alert-case link",
                        weight=5,
                        key="alert_id",
                        value=link_alert,
                    )
                )

        left_analysis = _normalize_text(left.entity_keys.get("analysis_id"))
        right_analysis = _normalize_text(right.entity_keys.get("analysis_id"))
        if left_analysis and right_analysis and left_analysis == right_analysis:
            non_time_reasons.append(
                _Reason(
                    code="same_analysis_id",
                    label="same analysis id",
                    weight=4,
                    key="analysis_id",
                    value=left_analysis,
                )
            )

        left_qf = _normalize_text(left.entity_keys.get("query_fingerprint"))
        right_qf = _normalize_text(right.entity_keys.get("query_fingerprint"))
        if left_qf and right_qf and left_qf == right_qf:
            non_time_reasons.append(
                _Reason(
                    code="same_query_fingerprint",
                    label="same query fingerprint",
                    weight=4,
                    key="query_fingerprint",
                    value=left_qf,
                )
            )

        left_hash = _normalize_text(left.entity_keys.get("file_hash"))
        right_hash = _normalize_text(right.entity_keys.get("file_hash"))
        if left_hash and right_hash and left_hash == right_hash:
            non_time_reasons.append(
                _Reason(
                    code="same_file_hash",
                    label="same file hash",
                    weight=5,
                    key="file_hash",
                    value=left_hash,
                )
            )

        left_filename = _normalize_token(left.entity_keys.get("filename"))
        right_filename = _normalize_token(right.entity_keys.get("filename"))
        if left_filename and right_filename and left_filename == right_filename:
            non_time_reasons.append(
                _Reason(
                    code="same_filename",
                    label="same filename",
                    weight=2,
                    key="filename",
                    value=left_filename,
                )
            )

        left_domain = _normalize_token(left.entity_keys.get("sender_domain"))
        right_domain = _normalize_token(right.entity_keys.get("sender_domain"))
        if left_domain and right_domain and left_domain == right_domain:
            non_time_reasons.append(
                _Reason(
                    code="same_sender_domain",
                    label="same sender domain",
                    weight=3,
                    key="sender_domain",
                    value=left_domain,
                )
            )

        left_url = _normalize_token(left.entity_keys.get("url_host"))
        right_url = _normalize_token(right.entity_keys.get("url_host"))
        if left_url and right_url and left_url == right_url:
            non_time_reasons.append(
                _Reason(
                    code="same_url_host",
                    label="same URL host",
                    weight=3,
                    key="url_host",
                    value=left_url,
                )
            )

        left_ip = _normalize_token(left.entity_keys.get("source_ip"))
        right_ip = _normalize_token(right.entity_keys.get("source_ip"))
        if left_ip and right_ip and left_ip == right_ip:
            non_time_reasons.append(
                _Reason(
                    code="same_source_ip",
                    label="same source IP",
                    weight=3,
                    key="source_ip",
                    value=left_ip,
                )
            )

        left_domain_generic = _normalize_token(left.entity_keys.get("domain"))
        right_domain_generic = _normalize_token(right.entity_keys.get("domain"))
        if left_domain_generic and right_domain_generic and left_domain_generic == right_domain_generic:
            non_time_reasons.append(
                _Reason(
                    code="same_domain",
                    label="same domain",
                    weight=3,
                    key="domain",
                    value=left_domain_generic,
                )
            )

        left_email = _normalize_token(left.entity_keys.get("email"))
        right_email = _normalize_token(right.entity_keys.get("email"))
        if left_email and right_email and left_email == right_email:
            non_time_reasons.append(
                _Reason(
                    code="same_email",
                    label="same email",
                    weight=2,
                    key="email",
                    value=left_email,
                )
            )

        left_path = _normalize_token(left.entity_keys.get("path"))
        right_path = _normalize_token(right.entity_keys.get("path"))
        if left_path and right_path and left_path == right_path:
            non_time_reasons.append(
                _Reason(
                    code="same_path",
                    label="same path",
                    weight=2,
                    key="path",
                    value=left_path,
                )
            )

        left_command = _normalize_token(left.entity_keys.get("command"))
        right_command = _normalize_token(right.entity_keys.get("command"))
        if left_command and right_command and left_command == right_command:
            non_time_reasons.append(
                _Reason(
                    code="same_command",
                    label="same command",
                    weight=3,
                    key="command",
                    value=left_command,
                )
            )

        left_service_values = self._entity_set(left.entity_keys, "service", "target")
        right_service_values = self._entity_set(right.entity_keys, "service", "target")
        shared_services = sorted(left_service_values.intersection(right_service_values))
        if shared_services:
            non_time_reasons.append(
                _Reason(
                    code="same_service",
                    label="same service/source",
                    weight=2,
                    key="service",
                    value=shared_services[0],
                )
            )

        left_owner = _normalize_text(left.owner_user_id or left.entity_keys.get("owner_user_id"))
        right_owner = _normalize_text(right.owner_user_id or right.entity_keys.get("owner_user_id"))
        if left_owner and right_owner and left_owner == right_owner:
            non_time_reasons.append(
                _Reason(
                    code="same_owner",
                    label="same owner",
                    weight=2,
                    key="owner_user_id",
                    value=left_owner,
                )
            )

        left_actor = _normalize_text(left.actor_user_id)
        right_actor = _normalize_text(right.actor_user_id)
        if left_actor and right_actor and left_actor == right_actor:
            non_time_reasons.append(
                _Reason(
                    code="same_actor",
                    label="same actor",
                    weight=1,
                    key="actor_user_id",
                    value=left_actor,
                )
            )

        left_ts = _to_utc_datetime(left.timestamp)
        right_ts = _to_utc_datetime(right.timestamp)
        delta_minutes = None
        if left_ts is not None and right_ts is not None:
            delta_seconds = abs((left_ts - right_ts).total_seconds())
            delta_minutes = int(delta_seconds // 60)

        include_time_only = (
            bool(delta_minutes is not None and delta_minutes <= 10 and left.event_type == right.event_type)
            and not non_time_reasons
        )
        if delta_minutes is not None and delta_minutes <= 10 and (non_time_reasons or include_time_only):
            reasons.append(
                _Reason(
                    code="same_time_window",
                    label="same time window",
                    detail="within 10 minutes",
                    weight=2,
                )
            )
        elif delta_minutes is not None and delta_minutes <= 30 and non_time_reasons:
            reasons.append(
                _Reason(
                    code="same_time_window",
                    label="same time window",
                    detail="within 30 minutes",
                    weight=1,
                )
            )

        reasons.extend(non_time_reasons)
        total_weight = sum(item.weight for item in reasons)
        if total_weight < 2:
            return []
        return reasons

    def _attach_correlation(self, events: List[_RawEvent]) -> None:
        if len(events) <= 1:
            for event in events:
                event.correlation_level = "none"
            return

        for i, event in enumerate(events):
            related_rows: List[Tuple[_RawEvent, List[_Reason], int, CorrelationLevel]] = []
            entity_accumulator: Dict[Tuple[str, str], Dict[str, Any]] = {}
            reason_counts: Dict[Tuple[str, str, str, str], int] = {}

            for j, other in enumerate(events):
                if i == j:
                    continue
                reasons = self._pair_reasons(event, other)
                if not reasons:
                    continue
                weight = sum(reason.weight for reason in reasons)
                level = self._pair_level(weight)
                if level == "none":
                    continue
                related_rows.append((other, reasons, weight, level))

                for reason in reasons:
                    reason_key = (
                        reason.code,
                        reason.label,
                        _normalize_text(reason.key),
                        _normalize_text(reason.value),
                    )
                    reason_counts[reason_key] = reason_counts.get(reason_key, 0) + 1
                    if reason.key and reason.value:
                        entity_key = (_normalize_text(reason.key), _normalize_text(reason.value))
                        if not entity_key[0] or not entity_key[1]:
                            continue
                        row = entity_accumulator.setdefault(
                            entity_key,
                            {
                                "key": entity_key[0],
                                "value": entity_key[1],
                                "match_event_ids": set(),
                                "reasons": set(),
                            },
                        )
                        row["match_event_ids"].add(other.id)
                        row["reasons"].add(reason.label)

            related_rows.sort(
                key=lambda row: (
                    {"strong": 3, "moderate": 2, "weak": 1, "none": 0}.get(row[3], 0),
                    row[2],
                    self._event_sort_key(row[0])[0],
                    row[0].id,
                ),
                reverse=True,
            )

            related_events: List[InvestigationRelatedEvent] = []
            for other, reasons, _weight, level in related_rows[:8]:
                related_events.append(
                    InvestigationRelatedEvent(
                        id=other.id,
                        event_type=other.event_type,  # type: ignore[arg-type]
                        timestamp=other.timestamp,
                        title=other.title,
                        severity=other.severity,
                        source_ref=other.source_ref,
                        correlation_level=level,
                        correlation_reasons=[self._reason_to_schema(reason) for reason in reasons],
                    )
                )

            related_entities: List[InvestigationRelatedEntity] = []
            for payload in sorted(
                entity_accumulator.values(),
                key=lambda row: (len(row["match_event_ids"]), row["key"], row["value"]),
                reverse=True,
            )[:10]:
                related_entities.append(
                    InvestigationRelatedEntity(
                        key=payload["key"],
                        value=payload["value"],
                        match_count=len(payload["match_event_ids"]),
                        reasons=sorted(payload["reasons"]),
                        related_event_ids=sorted(payload["match_event_ids"])[:20],
                    )
                )

            aggregate_reasons: List[InvestigationCorrelationReason] = []
            for (code, label, key, value), count in sorted(
                reason_counts.items(),
                key=lambda item: item[1],
                reverse=True,
            )[:8]:
                aggregate_reasons.append(
                    InvestigationCorrelationReason(
                        code=code,
                        label=label,
                        detail=f"Matched with {count} related event(s).",
                        key=key or None,
                        value=value or None,
                    )
                )

            strongest_level: CorrelationLevel = "none"
            if related_rows:
                strongest_level = related_rows[0][3]

            event.related_events = related_events
            event.related_entities = related_entities
            event.correlation_reasons = aggregate_reasons
            event.correlation_level = strongest_level

    def _to_timeline_items(self, db: Session, events: List[_RawEvent]) -> List[InvestigationTimelineItem]:
        user_ids: List[str] = []
        for event in events:
            if event.actor_user_id:
                user_ids.append(event.actor_user_id)
            if event.owner_user_id:
                user_ids.append(event.owner_user_id)
        user_map = build_user_summary_map(db=db, user_ids=user_ids, include_unknown=False)

        output: List[InvestigationTimelineItem] = []
        for event in events:
            actor_id = _normalize_text(event.actor_user_id)
            owner_id = _normalize_text(event.owner_user_id)
            output.append(
                InvestigationTimelineItem(
                    id=event.id,
                    tenant_id=event.tenant_id,
                    timestamp=event.timestamp,
                    event_type=event.event_type,  # type: ignore[arg-type]
                    severity=event.severity,
                    title=event.title,
                    summary=event.summary,
                    actor_user_id=actor_id or None,
                    actor=user_map.get(actor_id) if actor_id else None,
                    owner_user_id=owner_id or None,
                    owner=user_map.get(owner_id) if owner_id else None,
                    entity_keys=event.entity_keys,
                    source_ref=event.source_ref,
                    case_ids=event.case_ids,
                    correlation_level=event.correlation_level,
                    correlation_reasons=event.correlation_reasons,
                    related_entities=event.related_entities,
                    related_events=event.related_events,
                )
            )
        return output

    def get_timeline(
        self,
        *,
        db: Session,
        tenant_id: Optional[str],
        limit: int = 200,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        before: Optional[datetime] = None,
        event_types: Optional[str] = None,
        entity_key: Optional[str] = None,
        entity_value: Optional[str] = None,
    ) -> List[InvestigationTimelineItem]:
        tenant = _resolve_tenant_id(tenant_id)
        safe_limit = max(1, min(int(limit or 200), 500))
        selected_types = _parse_event_types_csv(event_types)
        source_limit = max(250, min(2000, safe_limit * 4))

        query_ids: List[str] = []
        file_ids: List[str] = []
        spam_ids: List[str] = []
        alert_ids: List[str] = []
        case_ids_hint: List[str] = []

        if "query" in selected_types:
            query_ids = [
                _normalize_text(row_id)
                for (row_id,) in (
                    _apply_time_filters(
                        db.query(SQLAnalysisLogModel.id).filter(SQLAnalysisLogModel.tenant_id == tenant),
                        SQLAnalysisLogModel.timestamp,
                        start=start,
                        end=end,
                        before=before,
                    )
                    .order_by(SQLAnalysisLogModel.timestamp.desc())
                    .limit(source_limit)
                    .all()
                )
                if _normalize_text(row_id)
            ]

        if "file_scan" in selected_types:
            file_ids = [
                _normalize_text(row_id)
                for (row_id,) in (
                    _apply_time_filters(
                        db.query(FileAnalysisLogModel.id).filter(FileAnalysisLogModel.tenant_id == tenant),
                        FileAnalysisLogModel.timestamp,
                        start=start,
                        end=end,
                        before=before,
                    )
                    .order_by(FileAnalysisLogModel.timestamp.desc())
                    .limit(source_limit)
                    .all()
                )
                if _normalize_text(row_id)
            ]

        if "spam_check" in selected_types:
            spam_ids = [
                _normalize_text(row_id)
                for (row_id,) in (
                    _apply_time_filters(
                        db.query(SpamAnalysisLogModel.id).filter(SpamAnalysisLogModel.tenant_id == tenant),
                        SpamAnalysisLogModel.timestamp,
                        start=start,
                        end=end,
                        before=before,
                    )
                    .order_by(SpamAnalysisLogModel.timestamp.desc())
                    .limit(source_limit)
                    .all()
                )
                if _normalize_text(row_id)
            ]

        if "alert" in selected_types:
            alert_ids = [
                _normalize_text(row_id)
                for (row_id,) in (
                    _apply_time_filters(
                        db.query(AlertModel.id).filter(AlertModel.tenant_id == tenant),
                        AlertModel.timestamp,
                        start=start,
                        end=end,
                        before=before,
                    )
                    .order_by(AlertModel.timestamp.desc())
                    .limit(source_limit)
                    .all()
                )
                if _normalize_text(row_id)
            ]

        if "case" in selected_types:
            case_ids_hint.extend(
                [
                    _normalize_text(row_id)
                    for (row_id,) in (
                        _apply_time_filters(
                            db.query(SecurityCaseModel.id).filter(SecurityCaseModel.tenant_id == tenant),
                            SecurityCaseModel.updated_at,
                            start=start,
                            end=end,
                            before=before,
                        )
                        .order_by(SecurityCaseModel.updated_at.desc())
                        .limit(source_limit)
                        .all()
                    )
                    if _normalize_text(row_id)
                ]
            )

        if "case_note" in selected_types:
            case_ids_hint.extend(
                [
                    _normalize_text(case_id)
                    for (case_id,) in (
                        _apply_time_filters(
                            db.query(SecurityCaseNoteModel.case_id).filter(SecurityCaseNoteModel.tenant_id == tenant),
                            SecurityCaseNoteModel.created_at,
                            start=start,
                            end=end,
                            before=before,
                        )
                        .order_by(SecurityCaseNoteModel.created_at.desc())
                        .limit(source_limit)
                        .all()
                    )
                    if _normalize_text(case_id)
                ]
            )

        if "case_alert_link" in selected_types:
            case_ids_hint.extend(
                [
                    _normalize_text(case_id)
                    for (case_id,) in (
                        _apply_time_filters(
                            db.query(AlertCaseLinkModel.case_id).filter(AlertCaseLinkModel.tenant_id == tenant),
                            AlertCaseLinkModel.linked_at,
                            start=start,
                            end=end,
                            before=before,
                        )
                        .order_by(AlertCaseLinkModel.linked_at.desc())
                        .limit(source_limit)
                        .all()
                    )
                    if _normalize_text(case_id)
                ]
            )

        source_case_map, alert_case_map, case_meta = self._resolve_case_links(
            db,
            tenant_id=tenant,
            query_ids=query_ids,
            file_ids=file_ids,
            spam_ids=spam_ids,
            alert_ids=alert_ids,
            case_ids_hint=self._dedupe_preserve(case_ids_hint),
        )

        events: List[_RawEvent] = []
        if "query" in selected_types:
            events.extend(
                self._build_query_events(
                    db,
                    tenant_id=tenant,
                    limit=source_limit,
                    start=start,
                    end=end,
                    before=before,
                    source_case_map=source_case_map,
                    alert_case_map=alert_case_map,
                    case_meta=case_meta,
                )
            )
        if "file_scan" in selected_types:
            events.extend(
                self._build_file_events(
                    db,
                    tenant_id=tenant,
                    limit=source_limit,
                    start=start,
                    end=end,
                    before=before,
                    source_case_map=source_case_map,
                    alert_case_map=alert_case_map,
                    case_meta=case_meta,
                )
            )
        if "spam_check" in selected_types:
            events.extend(
                self._build_spam_events(
                    db,
                    tenant_id=tenant,
                    limit=source_limit,
                    start=start,
                    end=end,
                    before=before,
                    source_case_map=source_case_map,
                    alert_case_map=alert_case_map,
                    case_meta=case_meta,
                )
            )
        if "alert" in selected_types:
            events.extend(
                self._build_alert_events(
                    db,
                    tenant_id=tenant,
                    limit=source_limit,
                    start=start,
                    end=end,
                    before=before,
                    source_case_map=source_case_map,
                    alert_case_map=alert_case_map,
                    case_meta=case_meta,
                )
            )
        if "case" in selected_types:
            events.extend(
                self._build_case_events(
                    db,
                    tenant_id=tenant,
                    limit=source_limit,
                    start=start,
                    end=end,
                    before=before,
                    source_case_map=source_case_map,
                    alert_case_map=alert_case_map,
                    case_meta=case_meta,
                )
            )
        if "case_note" in selected_types:
            events.extend(
                self._build_case_note_events(
                    db,
                    tenant_id=tenant,
                    limit=source_limit,
                    start=start,
                    end=end,
                    before=before,
                    case_meta=case_meta,
                    alert_case_map=alert_case_map,
                )
            )
        if "case_alert_link" in selected_types:
            events.extend(
                self._build_case_alert_link_events(
                    db,
                    tenant_id=tenant,
                    limit=source_limit,
                    start=start,
                    end=end,
                    before=before,
                    case_meta=case_meta,
                )
            )

        filtered = [
            event
            for event in events
            if self._event_matches_entity_filter(event, entity_key=entity_key, entity_value=entity_value)
        ]
        filtered.sort(key=self._event_sort_key, reverse=True)

        dedup: Dict[str, _RawEvent] = {}
        for event in filtered:
            dedup.setdefault(event.id, event)
        selected = list(dedup.values())[:safe_limit]

        self._attach_correlation(selected)
        return self._to_timeline_items(db, selected)
