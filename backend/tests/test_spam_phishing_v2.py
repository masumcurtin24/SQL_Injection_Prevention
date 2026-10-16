from __future__ import annotations

from copy import deepcopy

import pytest

from backend.services.defender_ai_service import DefenderAIService
from backend.services.spam_detection_service import SpamDetectionService


def _admin_token(client) -> str:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password-123"},
    )
    assert login.status_code == 200, login.text
    return login.json()["access_token"]


def _admin_headers_with_step_up(client, actions=None) -> dict:
    token = _admin_token(client)
    step_up = client.post(
        "/api/v1/auth/step-up",
        headers={"Authorization": f"Bearer {token}"},
        json={"password": "admin-password-123", "actions": actions or []},
    )
    assert step_up.status_code == 200, step_up.text
    step_up_token = step_up.json().get("step_up_token")
    assert step_up_token
    return {
        "Authorization": f"Bearer {token}",
        "X-Step-Up-Token": step_up_token,
    }


def _snapshot_service_state(service: SpamDetectionService) -> dict:
    return {
        "_blocklist_domains": set(service._blocklist_domains or set()),
        "_allowlist_domains": set(service._allowlist_domains or set()),
        "_domain_reputation": dict(service._domain_reputation or {}),
        "_thresholds_override": deepcopy(getattr(service, "_thresholds_override", None)),
        "_feature_weights_override": deepcopy(getattr(service, "_feature_weights_override", None)),
        "_calibration_override": deepcopy(getattr(service, "_calibration_override", None)),
        "_final_threshold_override": getattr(service, "_final_threshold_override", None),
        "_suspicious_tlds_override": deepcopy(getattr(service, "_suspicious_tlds_override", None)),
    }


def _restore_service_state(service: SpamDetectionService, snap: dict) -> None:
    service._blocklist_domains = snap["_blocklist_domains"]
    service._allowlist_domains = snap["_allowlist_domains"]
    service._domain_reputation = snap["_domain_reputation"]
    service._thresholds_override = snap["_thresholds_override"]
    service._feature_weights_override = snap["_feature_weights_override"]
    service._calibration_override = snap["_calibration_override"]
    service._final_threshold_override = snap["_final_threshold_override"]
    service._suspicious_tlds_override = snap["_suspicious_tlds_override"]


@pytest.mark.parametrize(
    ("spam_score", "category", "expected"),
    [
        (0.08, "safe", 0.92),
        (0.15, "not_spam", 0.85),
        (0.87, "spam", 0.87),
        (0.94, "phishing", 0.94),
    ],
)
def test_spam_decision_confidence_matches_selected_class(spam_score, category, expected):
    assert SpamDetectionService._compute_decision_confidence(spam_score, category) == pytest.approx(expected)


def test_spam_decision_confidence_stays_separate_from_ood_or_uncertainty():
    confidence = SpamDetectionService._compute_decision_confidence(
        spam_score=0.90,
        category="phishing",
        uncertainty_score=0.0,
        ood_score=0.60,
    )

    assert confidence == pytest.approx(0.90)


def test_spam_decision_confidence_clamps_inputs_and_does_not_invert_risk():
    spam_score = 0.08
    confidence = SpamDetectionService._compute_decision_confidence(spam_score, "safe")

    assert spam_score == pytest.approx(0.08)
    assert confidence == pytest.approx(0.92)
    assert SpamDetectionService._clamp01(-0.25) == 0.0
    assert SpamDetectionService._clamp01(1.25) == 1.0
    assert SpamDetectionService._compute_decision_confidence(-0.25, "phishing") == 0.0
    assert SpamDetectionService._compute_decision_confidence(1.25, "phishing") == 1.0


def test_spam_settings_exposes_phishing_v2_fields(client):
    token = _admin_token(client)
    res = client.get(
        "/api/v1/analyze-spam/settings",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200, res.text
    body = res.json()

    assert "thresholds" in body and isinstance(body["thresholds"], dict)
    for key in ("allow", "suspicious", "block", "ood"):
        assert key in body["thresholds"]
        assert isinstance(body["thresholds"][key], (float, int))
        assert 0.0 <= float(body["thresholds"][key]) <= 1.0
    assert "feature_weights" in body and isinstance(body["feature_weights"], dict)
    assert "calibration" in body and isinstance(body["calibration"], dict)
    assert "reputation_entries" in body
    assert "fraud_pattern_count" in body
    assert "fraud_pattern_version" in body


def test_spam_settings_update_accepts_v2_payload(client):
    headers = _admin_headers_with_step_up(client, actions=["spam.settings.update"])
    payload = {
        "thresholds": {"allow": 0.33, "suspicious": 0.57, "block": 0.84, "ood": 0.66},
        "feature_weights": {"transformer": 0.40, "reputation": 0.16},
        "calibration": {"a": 3.5, "b": -1.7},
    }
    res = client.put(
        "/api/v1/analyze-spam/settings",
        headers=headers,
        json=payload,
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body.get("updated") is True
    assert abs(float(body["thresholds"]["allow"]) - 0.33) < 1e-9
    assert abs(float(body["thresholds"]["suspicious"]) - 0.57) < 1e-9
    assert abs(float(body["thresholds"]["block"]) - 0.84) < 1e-9
    assert abs(float(body["thresholds"]["ood"]) - 0.66) < 1e-9
    assert abs(float(body["feature_weights"]["transformer"]) - 0.40) < 1e-9
    assert abs(float(body["feature_weights"]["reputation"]) - 0.16) < 1e-9


def test_spam_reputation_reload_endpoint(client):
    headers = _admin_headers_with_step_up(client, actions=["spam.settings.update"])
    res = client.post(
        "/api/v1/analyze-spam/reputation/reload",
        headers=headers,
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body.get("status") == "ok"
    assert isinstance((body.get("reputation") or {}).get("reloaded"), bool)


def test_spam_reputation_update_endpoint_runs_ingest(client, monkeypatch):
    import backend.scripts.update_spam_reputation_feed as updater

    headers = _admin_headers_with_step_up(client, actions=["spam.settings.update"])
    monkeypatch.setattr(updater, "main", lambda: 0)

    res = client.post(
        "/api/v1/analyze-spam/reputation/update",
        headers=headers,
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body.get("status") == "ok"
    assert int((body.get("upstream_ingest") or {}).get("exit_code", -1)) == 0
    assert isinstance((body.get("reputation") or {}).get("reloaded"), bool)


def test_spam_fraud_pattern_reload_endpoint(client):
    headers = _admin_headers_with_step_up(client, actions=["spam.settings.update"])
    res = client.post(
        "/api/v1/analyze-spam/reputation/fraud-patterns/reload",
        headers=headers,
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body.get("status") == "ok"
    fraud = body.get("fraud_patterns") or {}
    assert isinstance(fraud.get("reloaded"), bool)
    assert int(fraud.get("pattern_count") or 0) >= 1


def test_spam_feedback_endpoint_feeds_defender_auto_retrain(client, monkeypatch):
    token = _admin_token(client)
    headers = {"Authorization": f"Bearer {token}"}

    monkeypatch.setenv("DEFENDER_SPAM_AUTO_RETRAIN_ENABLED", "true")
    monkeypatch.setenv("DEFENDER_SPAM_AUTO_RETRAIN_MIN_FALSE_NEGATIVE_SAMPLES", "1")
    monkeypatch.setenv("DEFENDER_SPAM_AUTO_RETRAIN_COOLDOWN_MINUTES", "0")
    monkeypatch.setenv("DEFENDER_SPAM_AUTO_RETRAIN_PROMOTE_IF_BETTER", "false")

    service = DefenderAIService.get_instance()
    calls = {"create": 0, "run": 0}

    class _Job:
        def __init__(self, job_id: str, status: str):
            self.id = job_id
            self.status = status

    def _fake_create_training_job(*, db, domain, min_feedback_samples, promote_if_better, requested_by, notes):
        calls["create"] += 1
        assert domain == "spam"
        assert min_feedback_samples == 1
        assert promote_if_better is False
        assert "auto_false_negative" in str(notes or "")
        return _Job("job-auto-spam-feedback-route", "queued")

    def _fake_run_training_job(*, db, job_id):
        calls["run"] += 1
        assert job_id == "job-auto-spam-feedback-route"
        return _Job(job_id, "succeeded")

    monkeypatch.setattr(service, "create_training_job", _fake_create_training_job)
    monkeypatch.setattr(service, "run_training_job", _fake_run_training_job)

    res = client.post(
        "/api/v1/analyze-spam/feedback",
        headers=headers,
        json={
            "subject": "Payroll security check",
            "body_text": "Immediate verification required: https://payroll-verify-secure.com/session/update",
            "sender_email": "Payroll Team <security@corp-payroll.com>",
            "label": "Spam",
            "predicted_label": "Ham",
            "source": "human",
            "notes": "Analyst corrected false negative from spam analyzer page",
        },
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body.get("status") == "ok"
    auto = body.get("auto_retrain") or {}
    assert auto.get("triggered") is True
    assert auto.get("job_id") == "job-auto-spam-feedback-route"
    assert auto.get("job_status") == "succeeded"
    assert calls["create"] == 1
    assert calls["run"] == 1


def test_spam_analysis_returns_reputation_and_calibrated_breakdown(client):
    token = _admin_token(client)
    service = SpamDetectionService.get_instance()
    snapshot = _snapshot_service_state(service)
    service._blocklist_domains = set(service._blocklist_domains or set()) | {"phish-example.test"}
    service._thresholds_override = {"allow": 0.4, "suspicious": 0.58, "block": 0.85, "ood": 0.72}
    try:
        res = client.post(
            "/api/v1/analyze-spam/email",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "subject": "Urgent account verification required",
                "body_text": (
                    "Verify now via http://phish-example.test/login and "
                    "http://198.51.100.10/secure?token=%31%32. "
                    "Failure to act will suspend your payroll."
                ),
                "sender_email": "Payroll Team <security@corp-payroll.com>",
            },
        )
        assert res.status_code == 200, res.text
        body = res.json()
        sb = body.get("score_breakdown") or {}
        ui = body.get("url_indicators") or {}
        spam = body.get("spam_classification") or {}
        explanation = body.get("explanation") or {}

        assert isinstance(sb.get("final"), (float, int))
        assert isinstance(sb.get("decision_confidence"), (float, int))
        assert isinstance(sb.get("raw_fused"), (float, int))
        assert isinstance(sb.get("reputation"), (float, int))
        assert isinstance(sb.get("ood"), (float, int))
        assert isinstance(sb.get("thresholds"), dict)
        assert isinstance(spam.get("spam_score"), (float, int))
        assert isinstance(spam.get("decision_confidence"), (float, int))
        assert spam.get("spam_score") == pytest.approx(sb.get("final"))
        assert spam.get("decision_confidence") == pytest.approx(explanation.get("confidence"))
        assert explanation.get("spam_risk") == pytest.approx(spam.get("spam_score"))
        assert ui.get("blocklisted_count", 0) >= 1
        assert "reputation_score_max" in ui
        assert "reputation_score_avg" in ui
    finally:
        _restore_service_state(service, snapshot)


def test_spam_analysis_marks_ood_review_when_threshold_crossed(client):
    token = _admin_token(client)
    service = SpamDetectionService.get_instance()
    snapshot = _snapshot_service_state(service)
    service._thresholds_override = {"allow": 0.4, "suspicious": 0.6, "block": 0.9, "ood": 0.6}
    try:
        res = client.post(
            "/api/v1/analyze-spam/email",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "subject": "???",
                "body_text": "%%% ### ??? 12345 !!!",
                "sender_email": "noreply@example.com",
            },
        )
        assert res.status_code == 200, res.text
        body = res.json()
        label = str((body.get("spam_classification") or {}).get("classification_label") or "").lower()
        assert "ood" in label
        meta = body.get("meta_features") or {}
        assert isinstance(meta.get("ood_score"), (float, int))
        evidence = ((body.get("explanation") or {}).get("evidence") or [])
        evidence_ids = {str(e.get("id")) for e in evidence if isinstance(e, dict)}
        assert "ood_review_required" in evidence_ids
    finally:
        _restore_service_state(service, snapshot)


def test_spam_analysis_extracts_inline_subject_and_sender(client):
    token = _admin_token(client)
    res = client.post(
        "/api/v1/analyze-spam/email",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "body_text": (
                "Subject: Microsoft 365 Password Expires Today\n"
                "From: Security Team <security@corp-payroll.com>\n\n"
                "Re-authenticate now to avoid lockout:\n"
                "https://microsoft-credential-check.com/owa/auth"
            ),
        },
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body.get("received_subject") == "Microsoft 365 Password Expires Today"
    meta = body.get("meta_features") or {}
    assert bool(meta.get("parsed_inline_fields")) is True
    assert str(meta.get("sender") or "").lower().startswith("security team")


def test_spam_analysis_adds_campaign_signal_in_breakdown(client):
    token = _admin_token(client)
    service = SpamDetectionService.get_instance()
    snapshot = _snapshot_service_state(service)
    service._thresholds_override = {"allow": 0.40, "suspicious": 0.58, "block": 0.82, "ood": 0.70}
    service._feature_weights_override = {
        "classical": 0.18,
        "transformer": 0.30,
        "online": 0.08,
        "heuristic": 0.18,
        "reputation": 0.10,
        "campaign": 0.26,
    }
    try:
        res = client.post(
            "/api/v1/analyze-spam/email",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "subject": "URGENT Payroll Action Required",
                "body_text": (
                    "Our payroll migration failed. Re-authenticate now to avoid lockout: "
                    "https://payroll-verify-secure.com/session/update?id=884271 "
                    "Failure to verify may place your account on manual hold."
                ),
                "sender_email": "Payroll Team <security@corp-payroll.com>",
            },
        )
        assert res.status_code == 200, res.text
        body = res.json()
        score_breakdown = body.get("score_breakdown") or {}
        assert isinstance(score_breakdown.get("campaign"), (float, int))
        assert float(score_breakdown.get("campaign") or 0.0) > 0.0
        meta = body.get("meta_features") or {}
        match_ids = set(str(x) for x in (meta.get("campaign_match_ids") or []))
        assert "credential_lure_with_link" in match_ids or len(match_ids) > 0
    finally:
        _restore_service_state(service, snapshot)


def test_spam_analysis_flags_unauthorized_bank_transfer_lure(client):
    token = _admin_token(client)
    service = SpamDetectionService.get_instance()
    snapshot = _snapshot_service_state(service)
    service._thresholds_override = {"allow": 0.40, "suspicious": 0.50, "block": 0.80, "ood": 0.68}
    try:
        res = client.post(
            "/api/v1/analyze-spam/email",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "subject": "Suspicious Transfer Detected",
                "body_text": (
                    "A transfer of AUD 4,980 was initiated from your account. "
                    "If unauthorized, cancel now: "
                    "https://secure-bank-alerts.co/reverse "
                    "If no action is taken within 15 minutes, transfer will be processed."
                ),
            },
        )
        assert res.status_code == 200, res.text
        body = res.json()
        spam = body.get("spam_classification") or {}
        label = str(spam.get("classification_label") or "").lower()
        assert spam.get("is_spam") is True
        assert "ham" not in label

        meta = body.get("meta_features") or {}
        match_ids = set(str(x) for x in (meta.get("campaign_match_ids") or []))
        assert "bank_transfer_fraud_alert" in match_ids
        assert "urgency_pressure" in match_ids
    finally:
        _restore_service_state(service, snapshot)


def test_spam_analysis_detects_additional_common_fraud_campaigns(client):
    token = _admin_token(client)
    service = SpamDetectionService.get_instance()
    snapshot = _snapshot_service_state(service)
    service._thresholds_override = {"allow": 0.40, "suspicious": 0.50, "block": 0.80, "ood": 0.68}
    samples = [
        (
            {
                "subject": "Delivery Attempt Failed",
                "body_text": (
                    "We missed your package delivery. Update your street address and pay delivery fee now: "
                    "https://parcel-redelivery-notice.top/confirm "
                    "If not completed, your package will be returned to sender in 12 hours."
                ),
            },
            {"delivery_redelivery_phish", "urgency_pressure"},
        ),
        (
            {
                "subject": "Updated Wire Instructions for Invoice 9841",
                "body_text": (
                    "Invoice is past due. Our bank details changed and you must remit to the new beneficiary today: "
                    "https://vendor-payments-update.com/wire"
                ),
            },
            {"bec_invoice_payment_reroute"},
        ),
        (
            {
                "subject": "Microsoft Security Alert",
                "body_text": (
                    "Your computer is infected. Call support now and install AnyDesk immediately to fix this issue: "
                    "https://ms-security-support-help.top/session"
                ),
            },
            {"tech_support_remote_access_scam"},
        ),
    ]
    try:
        for payload, expected_ids in samples:
            res = client.post(
                "/api/v1/analyze-spam/email",
                headers={"Authorization": f"Bearer {token}"},
                json=payload,
            )
            assert res.status_code == 200, res.text
            body = res.json()
            spam = body.get("spam_classification") or {}
            label = str(spam.get("classification_label") or "").lower()
            assert spam.get("is_spam") is True
            assert "ham" not in label

            meta = body.get("meta_features") or {}
            match_ids = set(str(x) for x in (meta.get("campaign_match_ids") or []))
            assert expected_ids.intersection(match_ids), f"expected any of {expected_ids}, got {match_ids}"
    finally:
        _restore_service_state(service, snapshot)


def test_spam_analysis_flags_collaboration_credentials_sheet_lure(client):
    token = _admin_token(client)
    service = SpamDetectionService.get_instance()
    snapshot = _snapshot_service_state(service)
    service._thresholds_override = {"allow": 0.40, "suspicious": 0.50, "block": 0.80, "ood": 0.68}
    try:
        res = client.post(
            "/api/v1/analyze-spam/email",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "subject": "You were mentioned in Project Delta",
                "body_text": (
                    "Alex tagged you in an urgent comment: "
                    "'Can you review the updated credentials sheet now?'\n"
                    "View comment: https://teams-files-share.work/delta/comment/1902"
                ),
            },
        )
        assert res.status_code == 200, res.text
        body = res.json()
        spam = body.get("spam_classification") or {}
        label = str(spam.get("classification_label") or "").lower()
        assert spam.get("is_spam") is True
        assert "ham" not in label

        meta = body.get("meta_features") or {}
        match_ids = set(str(x) for x in (meta.get("campaign_match_ids") or []))
        assert "collaboration_credential_lure_with_link" in match_ids
    finally:
        _restore_service_state(service, snapshot)


def test_spam_analysis_detects_obfuscated_urls_and_fraud_pack_patterns(client):
    token = _admin_token(client)
    service = SpamDetectionService.get_instance()
    snapshot = _snapshot_service_state(service)
    service._thresholds_override = {"allow": 0.35, "suspicious": 0.50, "block": 0.80, "ood": 0.68}
    try:
        res = client.post(
            "/api/v1/analyze-spam/email",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "subject": "Action needed for your account",
                "body_text": (
                    "Please verify your account immediately at hxxps://secure-bank-alerts[.]co/reverse "
                    "to avoid transfer processing."
                ),
            },
        )
        assert res.status_code == 200, res.text
        body = res.json()
        url_indicators = body.get("url_indicators") or {}
        assert int(url_indicators.get("total_urls") or 0) >= 1
        spam = body.get("spam_classification") or {}
        assert bool(spam.get("is_spam")) is True
        meta = body.get("meta_features") or {}
        fraud_ids = set(str(x) for x in (meta.get("fraud_pattern_match_ids") or []))
        assert "bank_transfer_reversal_pressure" in fraud_ids or len(fraud_ids) > 0
    finally:
        _restore_service_state(service, snapshot)


def test_spam_analysis_flags_direct_money_request_with_spaced_domain_link(client):
    token = _admin_token(client)
    service = SpamDetectionService.get_instance()
    snapshot = _snapshot_service_state(service)
    service._thresholds_override = {"allow": 0.35, "suspicious": 0.50, "block": 0.80, "ood": 0.68}
    try:
        res = client.post(
            "/api/v1/analyze-spam/email",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "subject": "Immediate Transfer Request",
                "body_text": "send me $10000 USING THE FOLLOWING LINK\nWWW. SENDME.IE",
            },
        )
        assert res.status_code == 200, res.text
        body = res.json()
        spam = body.get("spam_classification") or {}
        assert bool(spam.get("is_spam")) is True
        label = str(spam.get("classification_label") or "").lower()
        assert "ham" not in label

        urls = body.get("url_indicators") or {}
        assert int(urls.get("total_urls") or 0) >= 1
        hosts = [str(h).lower() for h in (urls.get("hosts") or [])]
        assert any("sendme.ie" in h for h in hosts)

        score_breakdown = body.get("score_breakdown") or {}
        assert float(score_breakdown.get("final") or 0.0) >= 0.50
    finally:
        _restore_service_state(service, snapshot)


def test_spam_analysis_uses_header_auth_anomalies(client):
    token = _admin_token(client)
    service = SpamDetectionService.get_instance()
    snapshot = _snapshot_service_state(service)
    service._thresholds_override = {"allow": 0.40, "suspicious": 0.52, "block": 0.82, "ood": 0.68}
    try:
        res = client.post(
            "/api/v1/analyze-spam/email",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "subject": "Urgent payroll review",
                "body_text": "Review updated credentials sheet: https://teams-files-share.work/delta/comment/1902",
                "sender_email": "Payroll Team <security@corp-payroll.com>",
                "headers": {
                    "From": "Payroll Team <security@corp-payroll.com>",
                    "Reply-To": "helpdesk@payroll-reset-support.net",
                    "Return-Path": "<mailer@bulk-notify-gateway.biz>",
                    "Authentication-Results": "mx.example.net; spf=fail smtp.mailfrom=corp-payroll.com; dkim=fail header.d=corp-payroll.com; dmarc=fail header.from=corp-payroll.com",
                },
            },
        )
        assert res.status_code == 200, res.text
        body = res.json()
        meta = body.get("meta_features") or {}
        header_ind = meta.get("header_indicators") or {}
        assert str(header_ind.get("dmarc")) == "fail"
        assert bool(header_ind.get("reply_to_mismatch")) is True
        assert float((body.get("score_breakdown") or {}).get("header") or 0.0) > 0.0
        evidence = ((body.get("explanation") or {}).get("evidence") or [])
        evidence_ids = {str(e.get("id")) for e in evidence if isinstance(e, dict)}
        assert "header_auth_anomaly" in evidence_ids
    finally:
        _restore_service_state(service, snapshot)


def test_spam_url_extraction_ignores_sentence_boundary_artifacts(client):
    _ = _admin_token(client)
    service = SpamDetectionService.get_instance()
    text = "Thank you for your payment. Your invoice has been marked as paid."
    urls = service._extract_urls(text)
    hosts = [service._domain_of(u) for u in urls]

    assert "payment.your" not in hosts
    assert "discount.click" not in hosts
    assert len(urls) == 0


def test_spam_analysis_keeps_authentic_ato_url_ham(client):
    token = _admin_token(client)
    service = SpamDetectionService.get_instance()
    snapshot = _snapshot_service_state(service)
    service._allowlist_domains = set(service._allowlist_domains or set()) | {"ato.gov.au"}
    service._thresholds_override = {"allow": 0.40, "suspicious": 0.50, "block": 0.80, "ood": 0.68}
    try:
        res = client.post(
            "/api/v1/analyze-spam/email",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "subject": "Tax information",
                "body_text": "Please review information at https://www.ato.gov.au/",
                "sender_email": "noreply@ato.gov.au",
            },
        )
        assert res.status_code == 200, res.text
        body = res.json()
        spam = body.get("spam_classification") or {}
        assert spam.get("is_spam") is False, body
        assert str(spam.get("classification_label") or "").lower() == "ham"
        assert float(spam.get("spam_score") or 0.0) < 0.50

        urls = body.get("url_indicators") or {}
        assert int(urls.get("allowlisted_count") or 0) >= 1
        match_ids = set(str(x) for x in ((body.get("meta_features") or {}).get("campaign_match_ids") or []))
        assert "government_impersonation_payment" not in match_ids
    finally:
        _restore_service_state(service, snapshot)


def test_spam_analysis_parses_raw_rfc822_headers(client):
    token = _admin_token(client)
    service = SpamDetectionService.get_instance()
    snapshot = _snapshot_service_state(service)
    service._thresholds_override = {"allow": 0.40, "suspicious": 0.50, "block": 0.80, "ood": 0.68}
    try:
        raw_email = (
            "From: Payroll Team <security@corp-payroll.com>\n"
            "Reply-To: helpdesk@payroll-reset-support.net\n"
            "Return-Path: <mailer@bulk-notify-gateway.biz>\n"
            "Subject: Urgent payroll review\n"
            "Authentication-Results: mx.example.net; spf=fail smtp.mailfrom=corp-payroll.com; "
            "dkim=fail header.d=corp-payroll.com; dmarc=fail header.from=corp-payroll.com\n"
            "MIME-Version: 1.0\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "Review updated credentials sheet: https://teams-files-share.work/delta/comment/1902\n"
        )
        res = client.post(
            "/api/v1/analyze-spam/email",
            headers={"Authorization": f"Bearer {token}"},
            json={"body_text": raw_email},
        )
        assert res.status_code == 200, res.text
        body = res.json()
        assert body.get("received_subject") == "Urgent payroll review"
        meta = body.get("meta_features") or {}
        assert bool(meta.get("parsed_raw_email")) is True
        header_ind = meta.get("header_indicators") or {}
        assert str(header_ind.get("dmarc")) == "fail"
        assert bool(header_ind.get("reply_to_mismatch")) is True
        assert float((body.get("score_breakdown") or {}).get("header") or 0.0) > 0.0
    finally:
        _restore_service_state(service, snapshot)


def test_spam_analysis_flags_brand_lookalike_domain(client):
    token = _admin_token(client)
    service = SpamDetectionService.get_instance()
    snapshot = _snapshot_service_state(service)
    service._thresholds_override = {"allow": 0.40, "suspicious": 0.50, "block": 0.80, "ood": 0.68}
    try:
        res = client.post(
            "/api/v1/analyze-spam/email",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "subject": "Microsoft security alert",
                "body_text": "Re-authenticate now: https://login-micr0soft-security.com/verify",
                "sender_email": "security@login-micr0soft-security.com",
            },
        )
        assert res.status_code == 200, res.text
        body = res.json()
        urls = body.get("url_indicators") or {}
        assert int(urls.get("brand_impersonation_count") or 0) >= 1
        assert "microsoft" in {str(x) for x in (urls.get("impersonated_brands") or [])}
        evidence_ids = {
            str(e.get("id"))
            for e in (((body.get("explanation") or {}).get("evidence") or []))
            if isinstance(e, dict)
        }
        assert "brand_lookalike_domain" in evidence_ids
        assert bool((body.get("spam_classification") or {}).get("is_spam")) is True
    finally:
        _restore_service_state(service, snapshot)


def test_spam_campaign_scores_text_only_bec_and_credential_requests(client):
    _ = _admin_token(client)
    service = SpamDetectionService.get_instance()
    samples = [
        (
            "Can you buy 10 gift cards for the client meeting and send me the codes privately?",
            {"gift_card_bec", "credential_collection_request"},
        ),
        (
            "Reply with your employee ID and password so we can complete the security audit.",
            {"credential_collection_request"},
        ),
        (
            "This is the CEO. I need you to process an urgent confidential payment within the next 15 minutes.",
            {"executive_urgent_payment_no_link"},
        ),
    ]

    for text, expected_ids in samples:
        bundle = service._modern_campaign_pattern_score(
            subject="",
            body_text=text,
            sender_email=None,
            url_indicators=service._url_indicators(text),
        )
        match_ids = {str(item.get("id")) for item in (bundle.get("matches") or [])}
        assert expected_ids.intersection(match_ids), f"expected any of {expected_ids}, got {match_ids}"
        assert float(bundle.get("score") or 0.0) >= 0.24


def test_spam_analysis_closes_docx_gap_samples(client):
    token = _admin_token(client)
    service = SpamDetectionService.get_instance()
    snapshot = _snapshot_service_state(service)
    service._thresholds_override = {"allow": 0.40, "suspicious": 0.50, "block": 0.80, "ood": 0.68}
    samples = [
        (
            "Unlock your exclusive discount - 90% off today only!",
            {"promotion_prize_scam"},
        ),
        (
            "You have been pre-approved for a $50,000 loan.",
            {"loan_credit_offer_scam", "finance_impersonation"},
        ),
        (
            "Get rich quick! Earn $5,000 a week from home.",
            {"promotion_prize_scam", "investment_or_refund_scam"},
        ),
        (
            "Final notice: Renew your subscription today or lose access.",
            {"renewal_or_warranty_pressure", "urgency_pressure"},
        ),
        (
            "Your account has unusual activity - login to secure it.",
            {"account_lockout_verification_lure"},
        ),
        (
            "Your package is waiting! Confirm delivery: http://track-order.example",
            {"delivery_redelivery_phish"},
        ),
    ]
    try:
        for body_text, expected_ids in samples:
            res = client.post(
                "/api/v1/analyze-spam/email",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "subject": "",
                    "body_text": body_text,
                    "sender_email": "noreply@example.com",
                },
            )
            assert res.status_code == 200, res.text
            body = res.json()
            spam = body.get("spam_classification") or {}
            assert bool(spam.get("is_spam")) is True, (body_text, body)
            assert "ham" not in str(spam.get("classification_label") or "").lower(), (body_text, body)
            assert float(spam.get("spam_score") or 0.0) >= 0.50, (body_text, body)

            meta = body.get("meta_features") or {}
            match_ids = set(str(x) for x in (meta.get("campaign_match_ids") or []))
            assert expected_ids.intersection(match_ids), f"expected any of {expected_ids}, got {match_ids} for '{body_text}'"
    finally:
        _restore_service_state(service, snapshot)
