import uuid
from datetime import datetime, timezone

from backend.core.database import SessionLocal
from backend.core.models import DefenderModelRegistry
from backend.services.defender_ai_service import DefenderAIService


def test_activate_active_models_prefers_registry_active_for_spam(client, monkeypatch, tmp_path):
    service = DefenderAIService.get_instance()
    artifact_path = tmp_path / "spam-active.joblib"
    artifact_path.write_bytes(b"placeholder")

    inserted_id = str(uuid.uuid4())
    applied_calls = []

    def _fake_apply(self, domain: str, artifact_path: str) -> bool:  # pragma: no cover - exercised via service call
        applied_calls.append((domain, artifact_path))
        return True

    monkeypatch.setattr(DefenderAIService, "_apply_model_runtime", _fake_apply)

    with SessionLocal() as db:
        row = DefenderModelRegistry(
            id=inserted_id,
            timestamp=datetime.now(timezone.utc),
            domain="spam",
            model_name="spam_detector_logreg_tfidf",
            version=f"test-startup-{uuid.uuid4().hex[:8]}",
            stage="active",
            artifact_path=str(artifact_path),
            promoted_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
            notes="startup activation regression test",
        )
        db.add(row)
        db.commit()

        summary = service.activate_active_models(db=db, domains=["spam"])

        db.query(DefenderModelRegistry).filter(DefenderModelRegistry.id == inserted_id).delete()
        db.commit()

    assert applied_calls == [("spam", str(artifact_path))]
    assert summary["spam"]["applied"] is True
    assert summary["spam"]["registry_id"] == inserted_id
    assert summary["spam"]["artifact_path"] == str(artifact_path)
