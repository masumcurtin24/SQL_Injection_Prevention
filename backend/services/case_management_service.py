from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from backend.core.models import Alert as AlertModel
from backend.core.models import DEFAULT_TENANT_ID, AlertCaseLink, SecurityCase, SecurityCaseNote
from backend.utils.user_summary import build_user_summary_map
from backend.utils.logging_utils import setup_logger

logger = setup_logger(__name__)

_VALID_STATUSES = {"new", "triaged", "investigating", "contained", "closed"}
_VALID_SEVERITIES = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _to_utc_datetime(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            return None
    return None


class CaseManagementService:
    _instance: Optional["CaseManagementService"] = None
    _initialized_flag: bool = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(CaseManagementService, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if CaseManagementService._initialized_flag:
            return
        logger.info("Initializing CaseManagementService...")
        CaseManagementService._initialized_flag = True
        logger.info("CaseManagementService initialized successfully.")

    @classmethod
    def get_instance(cls) -> "CaseManagementService":
        if not cls._initialized_flag or cls._instance is None:
            raise RuntimeError("CaseManagementService is not initialized.")
        return cls._instance

    @classmethod
    def is_initialized(cls) -> bool:
        return bool(cls._initialized_flag)

    def _normalize_status(self, value: str) -> str:
        normalized = str(value or "").strip().lower()
        if normalized not in _VALID_STATUSES:
            raise ValueError(f"Invalid case status: {value}")
        return normalized

    def _normalize_severity(self, value: str) -> str:
        normalized = str(value or "").strip().lower()
        if normalized not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid case severity: {value}")
        return _VALID_SEVERITIES[normalized]

    @staticmethod
    def _resolve_tenant_id(tenant_id: Optional[str]) -> str:
        value = str(tenant_id or "").strip()
        return value or DEFAULT_TENANT_ID

    def _append_timeline(
        self,
        case: SecurityCase,
        *,
        actor_user_id: Optional[str],
        action: str,
        note: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        timeline = list(case.timeline or [])
        timeline.append(
            {
                "timestamp": _utcnow().isoformat(),
                "actor_user_id": actor_user_id,
                "action": action,
                "note": note,
                "details": details or None,
            }
        )
        case.timeline = timeline

    def _list_case_notes(
        self,
        db: Session,
        *,
        case_id: str,
        tenant_id: Optional[str] = None,
        limit: int = 500,
    ) -> List[SecurityCaseNote]:
        tenant = self._resolve_tenant_id(tenant_id)
        safe_limit = max(1, min(int(limit or 500), 2000))
        return (
            db.query(SecurityCaseNote)
            .filter(SecurityCaseNote.tenant_id == tenant, SecurityCaseNote.case_id == case_id)
            .order_by(SecurityCaseNote.created_at.desc())
            .limit(safe_limit)
            .all()
        )

    def _list_alert_links(
        self,
        db: Session,
        *,
        case_id: str,
        tenant_id: Optional[str] = None,
        limit: int = 500,
    ) -> List[AlertCaseLink]:
        tenant = self._resolve_tenant_id(tenant_id)
        safe_limit = max(1, min(int(limit or 500), 2000))
        return (
            db.query(AlertCaseLink)
            .filter(AlertCaseLink.tenant_id == tenant, AlertCaseLink.case_id == case_id)
            .order_by(AlertCaseLink.linked_at.desc())
            .limit(safe_limit)
            .all()
        )

    def _build_activity_feed(
        self,
        *,
        case: SecurityCase,
        tenant_id: Optional[str],
        notes: List[SecurityCaseNote],
        alert_links: List[AlertCaseLink],
    ) -> List[Dict[str, Any]]:
        tenant = self._resolve_tenant_id(tenant_id)
        activity: List[Dict[str, Any]] = []
        note_ids_in_timeline: set[str] = set()
        link_alert_ids_in_timeline: set[str] = set()

        for raw_item in list(case.timeline or []):
            if not isinstance(raw_item, dict):
                continue
            details = raw_item.get("details")
            if not isinstance(details, dict):
                details = None
            if details:
                note_id = str(details.get("note_id") or "").strip()
                if note_id:
                    note_ids_in_timeline.add(note_id)
                alert_id = str(details.get("alert_id") or "").strip()
                if alert_id:
                    link_alert_ids_in_timeline.add(alert_id)
            activity.append(
                {
                    "tenant_id": tenant,
                    "timestamp": raw_item.get("timestamp"),
                    "actor_user_id": raw_item.get("actor_user_id"),
                    "action": str(raw_item.get("action") or "case.activity"),
                    "note": raw_item.get("note"),
                    "details": details,
                }
            )

        for note_row in notes:
            if note_row.id in note_ids_in_timeline:
                continue
            activity.append(
                {
                    "tenant_id": tenant,
                    "timestamp": note_row.created_at,
                    "actor_user_id": note_row.author_user_id,
                    "action": "case.note",
                    "note": note_row.note,
                    "details": {"note_id": note_row.id},
                }
            )

        for link_row in alert_links:
            if link_row.alert_id in link_alert_ids_in_timeline:
                continue
            activity.append(
                {
                    "tenant_id": tenant,
                    "timestamp": link_row.linked_at,
                    "actor_user_id": link_row.linked_by_user_id,
                    "action": "case.alert.linked",
                    "note": link_row.note,
                    "details": {"alert_id": link_row.alert_id, "link_id": link_row.id},
                }
            )

        activity.sort(
            key=lambda item: _to_utc_datetime(item.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )
        return activity

    def _to_case_detail_payload(
        self,
        db: Session,
        *,
        case: SecurityCase,
        tenant_id: Optional[str],
    ) -> Dict[str, Any]:
        tenant = self._resolve_tenant_id(tenant_id)
        notes = self._list_case_notes(db=db, case_id=case.id, tenant_id=tenant)
        alert_links = self._list_alert_links(db=db, case_id=case.id, tenant_id=tenant)
        activity = self._build_activity_feed(case=case, tenant_id=tenant, notes=notes, alert_links=alert_links)
        timeline_entries = list(case.timeline or [])

        user_ids: set[str] = set()
        for candidate in [case.owner_user_id, case.created_by_user_id]:
            text = str(candidate or "").strip()
            if text:
                user_ids.add(text)
        for entry in timeline_entries:
            if not isinstance(entry, dict):
                continue
            text = str(entry.get("actor_user_id") or "").strip()
            if text:
                user_ids.add(text)
        for note_row in notes:
            text = str(note_row.author_user_id or "").strip()
            if text:
                user_ids.add(text)
        for link_row in alert_links:
            text = str(link_row.linked_by_user_id or "").strip()
            if text:
                user_ids.add(text)
        for entry in activity:
            text = str(entry.get("actor_user_id") or "").strip()
            if text:
                user_ids.add(text)
        user_map = build_user_summary_map(db=db, user_ids=user_ids, include_unknown=False)

        enriched_timeline: List[Dict[str, Any]] = []
        for raw_item in timeline_entries:
            if not isinstance(raw_item, dict):
                continue
            item = dict(raw_item)
            actor_id = str(item.get("actor_user_id") or "").strip()
            item["actor"] = user_map.get(actor_id) if actor_id else None
            enriched_timeline.append(item)

        enriched_activity: List[Dict[str, Any]] = []
        for raw_item in activity:
            item = dict(raw_item)
            actor_id = str(item.get("actor_user_id") or "").strip()
            item["actor"] = user_map.get(actor_id) if actor_id else None
            enriched_activity.append(item)

        return {
            "id": case.id,
            "tenant_id": tenant,
            "created_at": case.created_at,
            "updated_at": case.updated_at,
            "status": case.status,
            "severity": case.severity,
            "title": case.title,
            "description": case.description,
            "domain": case.domain,
            "source_type": case.source_type,
            "source_id": case.source_id,
            "owner_user_id": case.owner_user_id,
            "owner": user_map.get(str(case.owner_user_id or "").strip()) if case.owner_user_id else None,
            "created_by_user_id": case.created_by_user_id,
            "created_by": user_map.get(str(case.created_by_user_id or "").strip()) if case.created_by_user_id else None,
            "tags": case.tags or [],
            "evidence": case.evidence or [],
            "timeline": enriched_timeline,
            "notes": [
                {
                    "id": row.id,
                    "case_id": row.case_id,
                    "tenant_id": row.tenant_id,
                    "created_at": row.created_at,
                    "author_user_id": row.author_user_id,
                    "author": user_map.get(str(row.author_user_id or "").strip()) if row.author_user_id else None,
                    "note": row.note,
                }
                for row in notes
            ],
            "alert_links": [
                {
                    "id": row.id,
                    "case_id": row.case_id,
                    "tenant_id": row.tenant_id,
                    "alert_id": row.alert_id,
                    "linked_at": row.linked_at,
                    "linked_by_user_id": row.linked_by_user_id,
                    "linked_by": user_map.get(str(row.linked_by_user_id or "").strip()) if row.linked_by_user_id else None,
                    "note": row.note,
                }
                for row in alert_links
            ],
            "activity": enriched_activity,
        }

    def _link_alert_no_commit(
        self,
        db: Session,
        *,
        case: SecurityCase,
        tenant_id: Optional[str],
        alert_id: str,
        actor_user_id: str,
        note: Optional[str] = None,
    ) -> AlertCaseLink:
        tenant = self._resolve_tenant_id(tenant_id)
        normalized_alert_id = str(alert_id or "").strip()
        if not normalized_alert_id:
            raise ValueError("Alert ID is required for linking.")

        exists = (
            db.query(AlertModel.id)
            .filter(AlertModel.tenant_id == tenant, AlertModel.id == normalized_alert_id)
            .first()
        )
        if not exists:
            raise ValueError(f"Alert '{normalized_alert_id}' was not found.")

        link = (
            db.query(AlertCaseLink)
            .filter(
                AlertCaseLink.tenant_id == tenant,
                AlertCaseLink.case_id == case.id,
                AlertCaseLink.alert_id == normalized_alert_id,
            )
            .first()
        )
        if link is not None:
            return link

        link = AlertCaseLink(
            tenant_id=tenant,
            case_id=case.id,
            alert_id=normalized_alert_id,
            linked_by_user_id=str(actor_user_id),
            note=str(note or "").strip() or None,
        )
        db.add(link)
        db.flush()
        case.updated_at = _utcnow()
        self._append_timeline(
            case,
            actor_user_id=actor_user_id,
            action="case.alert.linked",
            note=link.note or "Linked alert to case",
            details={"alert_id": normalized_alert_id, "link_id": link.id},
        )
        return link

    def create_case(
        self,
        db: Session,
        *,
        tenant_id: Optional[str],
        created_by_user_id: str,
        title: str,
        description: Optional[str],
        severity: str,
        domain: Optional[str],
        source_type: Optional[str],
        source_id: Optional[str],
        owner_user_id: Optional[str],
        tags: Optional[List[str]],
        evidence: Optional[List[Dict[str, Any]]],
        alert_ids: Optional[List[str]] = None,
    ) -> SecurityCase:
        tenant = self._resolve_tenant_id(tenant_id)
        title_normalized = str(title or "").strip()
        if not title_normalized:
            raise ValueError("Case title is required.")
        normalized_severity = self._normalize_severity(severity or "Medium")
        case = SecurityCase(
            tenant_id=tenant,
            title=title_normalized,
            description=str(description or "").strip() or None,
            severity=normalized_severity,
            status="new",
            domain=str(domain or "").strip().lower() or None,
            source_type=str(source_type or "").strip().lower() or None,
            source_id=str(source_id or "").strip() or None,
            owner_user_id=str(owner_user_id or "").strip() or None,
            created_by_user_id=str(created_by_user_id),
            updated_at=_utcnow(),
        )
        case.tags = [str(tag).strip() for tag in (tags or []) if str(tag).strip()]
        case.evidence = evidence or []
        case.timeline = []
        self._append_timeline(
            case,
            actor_user_id=created_by_user_id,
            action="case.created",
            note="Case created",
            details={
                "severity": normalized_severity,
                "domain": case.domain,
                "source_type": case.source_type,
                "source_id": case.source_id,
            },
        )
        if case.owner_user_id:
            self._append_timeline(
                case,
                actor_user_id=created_by_user_id,
                action="case.assigned",
                note="Initial owner assigned",
                details={"owner_user_id": case.owner_user_id},
            )

        db.add(case)
        db.flush()
        for alert_id in alert_ids or []:
            self._link_alert_no_commit(
                db=db,
                case=case,
                tenant_id=tenant,
                alert_id=alert_id,
                actor_user_id=str(created_by_user_id),
                note="Linked during case creation",
            )
        db.commit()
        db.refresh(case)
        return case

    def get_case_by_id(self, db: Session, case_id: str, tenant_id: Optional[str] = None) -> Optional[SecurityCase]:
        tenant = self._resolve_tenant_id(tenant_id)
        return db.query(SecurityCase).filter(SecurityCase.tenant_id == tenant, SecurityCase.id == case_id).first()

    def get_case_detail_payload(
        self,
        db: Session,
        *,
        case_id: str,
        tenant_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        tenant = self._resolve_tenant_id(tenant_id)
        case = self.get_case_by_id(db=db, case_id=case_id, tenant_id=tenant)
        if case is None:
            return None
        return self._to_case_detail_payload(db=db, case=case, tenant_id=tenant)

    def list_cases(
        self,
        db: Session,
        *,
        tenant_id: Optional[str],
        page: int,
        page_size: int,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        owner_user_id: Optional[str] = None,
        search_term: Optional[str] = None,
    ) -> tuple[List[Dict[str, Any]], int, int, Dict[str, int]]:
        tenant = self._resolve_tenant_id(tenant_id)
        query = db.query(SecurityCase).filter(SecurityCase.tenant_id == tenant)

        if status:
            query = query.filter(SecurityCase.status == self._normalize_status(status))
        if severity:
            query = query.filter(SecurityCase.severity == self._normalize_severity(severity))
        if owner_user_id:
            query = query.filter(SecurityCase.owner_user_id == str(owner_user_id).strip())
        if search_term:
            term = str(search_term).strip()
            if term:
                like = f"%{term}%"
                query = query.filter(
                    or_(
                        SecurityCase.id.ilike(like),
                        SecurityCase.title.ilike(like),
                        SecurityCase.description.ilike(like),
                        SecurityCase.source_id.ilike(like),
                        SecurityCase._tags_json.ilike(like),
                    )
                )

        total_cases = int(query.count())
        total_pages = (total_cases + page_size - 1) // page_size if total_cases > 0 else 0
        rows = (
            query.order_by(SecurityCase.updated_at.desc(), SecurityCase.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )

        grouped = (
            db.query(SecurityCase.status, func.count(SecurityCase.id))
            .filter(SecurityCase.tenant_id == tenant)
            .group_by(SecurityCase.status)
            .all()
        )
        status_counts = {str(status_name): int(count) for status_name, count in grouped}
        for status_name in _VALID_STATUSES:
            status_counts.setdefault(status_name, 0)
        user_ids: set[str] = set()
        for row in rows:
            for candidate in [row.owner_user_id, row.created_by_user_id]:
                text = str(candidate or "").strip()
                if text:
                    user_ids.add(text)
        user_map = build_user_summary_map(db=db, user_ids=user_ids, include_unknown=False)

        payload_rows: List[Dict[str, Any]] = []
        for row in rows:
            owner_id = str(row.owner_user_id or "").strip()
            creator_id = str(row.created_by_user_id or "").strip()
            payload_rows.append(
                {
                    "id": row.id,
                    "tenant_id": row.tenant_id,
                    "created_at": row.created_at,
                    "updated_at": row.updated_at,
                    "status": row.status,
                    "severity": row.severity,
                    "title": row.title,
                    "domain": row.domain,
                    "source_type": row.source_type,
                    "source_id": row.source_id,
                    "owner_user_id": row.owner_user_id,
                    "owner": user_map.get(owner_id) if owner_id else None,
                    "created_by_user_id": row.created_by_user_id,
                    "created_by": user_map.get(creator_id) if creator_id else None,
                    "tags": row.tags or [],
                }
            )

        return payload_rows, total_cases, total_pages, status_counts

    def update_status(
        self,
        db: Session,
        *,
        case: SecurityCase,
        new_status: str,
        actor_user_id: str,
        note: Optional[str] = None,
    ) -> SecurityCase:
        normalized_status = self._normalize_status(new_status)
        previous_status = case.status
        case.status = normalized_status
        case.updated_at = _utcnow()
        self._append_timeline(
            case,
            actor_user_id=actor_user_id,
            action="case.status.update",
            note=note or f"Status changed to {normalized_status}",
            details={"previous_status": previous_status, "new_status": normalized_status},
        )
        db.add(case)
        db.commit()
        db.refresh(case)
        return case

    def assign_owner(
        self,
        db: Session,
        *,
        case: SecurityCase,
        owner_user_id: Optional[str],
        actor_user_id: str,
        note: Optional[str] = None,
    ) -> SecurityCase:
        previous_owner = case.owner_user_id
        next_owner = str(owner_user_id or "").strip() or None
        case.owner_user_id = next_owner
        case.updated_at = _utcnow()
        self._append_timeline(
            case,
            actor_user_id=actor_user_id,
            action="case.assigned",
            note=note or ("Owner cleared" if next_owner is None else "Owner updated"),
            details={"previous_owner_user_id": previous_owner, "owner_user_id": next_owner},
        )
        db.add(case)
        db.commit()
        db.refresh(case)
        return case

    def add_note(
        self,
        db: Session,
        *,
        case: SecurityCase,
        actor_user_id: str,
        note: str,
    ) -> SecurityCase:
        note_text = str(note or "").strip()
        if not note_text:
            raise ValueError("Case note cannot be empty.")
        note_row = SecurityCaseNote(
            case_id=case.id,
            author_user_id=str(actor_user_id),
            note=note_text,
        )
        db.add(note_row)
        db.flush()
        case.updated_at = _utcnow()
        self._append_timeline(
            case,
            actor_user_id=actor_user_id,
            action="case.note",
            note=note_text,
            details={"note_id": note_row.id},
        )
        db.add(case)
        db.commit()
        db.refresh(case)
        return case

    def link_alert(
        self,
        db: Session,
        *,
        case: SecurityCase,
        tenant_id: Optional[str],
        alert_id: str,
        actor_user_id: str,
        note: Optional[str] = None,
    ) -> SecurityCase:
        self._link_alert_no_commit(
            db=db,
            case=case,
            tenant_id=tenant_id,
            alert_id=alert_id,
            actor_user_id=actor_user_id,
            note=note,
        )
        db.add(case)
        db.commit()
        db.refresh(case)
        return case

    def list_case_notes(
        self,
        db: Session,
        *,
        case_id: str,
        tenant_id: Optional[str],
        limit: int = 500,
    ) -> List[SecurityCaseNote]:
        return self._list_case_notes(db=db, case_id=case_id, tenant_id=tenant_id, limit=limit)

    def list_case_alert_links(
        self,
        db: Session,
        *,
        case_id: str,
        tenant_id: Optional[str],
        limit: int = 500,
    ) -> List[AlertCaseLink]:
        return self._list_alert_links(db=db, case_id=case_id, tenant_id=tenant_id, limit=limit)

    def list_case_activity(
        self,
        db: Session,
        *,
        case: SecurityCase,
        tenant_id: Optional[str],
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        notes = self._list_case_notes(db=db, case_id=case.id, tenant_id=tenant_id, limit=limit)
        links = self._list_alert_links(db=db, case_id=case.id, tenant_id=tenant_id, limit=limit)
        activity = self._build_activity_feed(case=case, tenant_id=tenant_id, notes=notes, alert_links=links)[: max(1, min(limit, 2000))]
        actor_ids = [str(item.get("actor_user_id") or "").strip() for item in activity]
        user_map = build_user_summary_map(db=db, user_ids=actor_ids, include_unknown=False)
        enriched: List[Dict[str, Any]] = []
        for item in activity:
            next_item = dict(item)
            actor_id = str(next_item.get("actor_user_id") or "").strip()
            next_item["actor"] = user_map.get(actor_id) if actor_id else None
            enriched.append(next_item)
        return enriched

    def get_stats(self, db: Session, *, tenant_id: Optional[str]) -> Dict[str, Any]:
        tenant = self._resolve_tenant_id(tenant_id)
        grouped = (
            db.query(SecurityCase.status, func.count(SecurityCase.id))
            .filter(SecurityCase.tenant_id == tenant)
            .group_by(SecurityCase.status)
            .all()
        )
        by_status = {str(status_name): int(count) for status_name, count in grouped}
        total = int(sum(by_status.values()))
        for status_name in _VALID_STATUSES:
            by_status.setdefault(status_name, 0)
        closed = int(by_status.get("closed", 0))
        return {
            "total_cases": total,
            "open_cases": total - closed,
            "closed_cases": closed,
            "by_status": by_status,
        }
