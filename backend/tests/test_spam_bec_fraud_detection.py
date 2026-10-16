from __future__ import annotations

import pytest

from backend.services.spam_detection_service import SpamDetectionService


def _service() -> SpamDetectionService:
    svc = object.__new__(SpamDetectionService)
    svc._blocklist_domains = set()
    svc._allowlist_domains = {"example.com", "corp.example"}
    svc._domain_reputation = {
        "payroll-verify-secure.com": 0.98,
        "credential-reset.top": 0.90,
        "vendor-payments-update.com": 0.88,
        "secure-login-alerts.top": 0.92,
    }
    svc._fraud_pattern_pack = {"version": "test", "patterns": []}
    return svc


def _bec(subject: str, body: str, sender: str = "Sender <sender@example.net>") -> dict:
    svc = _service()
    text = f"{subject}\n{body}"
    url_indicators = svc._url_indicators(text)
    headers = svc._header_auth_indicators(
        headers=None,
        sender_email=sender,
        url_hosts=url_indicators.get("hosts"),
    )
    return svc.detect_business_email_compromise_signals(
        message=body,
        sender=sender,
        subject=subject,
        url_indicators=url_indicators,
        header_indicators=headers,
    )


def _admin_token(client) -> str:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password-123"},
    )
    assert login.status_code == 200, login.text
    return login.json()["access_token"]


def test_gift_card_fraud_high_risk_endpoint(client):
    token = _admin_token(client)
    res = client.post(
        "/api/v1/analyze-spam/email",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "subject": "Quick task before board call",
            "body_text": (
                "I need you to buy 10 gift cards (200 each) for client incentives. "
                "Send photos of card numbers and PINs immediately. "
                "I am in a meeting and cannot take calls. - Alex (Sent from mobile)"
            ),
            "sender_email": "Alex <alex.accounting@mobile-mail.example>",
        },
    )

    assert res.status_code == 200, res.text
    body = res.json()
    spam = body.get("spam_classification") or {}
    score_breakdown = body.get("score_breakdown") or {}
    meta = body.get("meta_features") or {}
    display = body.get("decision_display") or {}

    assert float(spam.get("spam_score") or 0.0) >= 0.78
    assert float(score_breakdown.get("heuristic") or 0.0) >= 0.80
    assert float(score_breakdown.get("fraud_pattern") or 0.0) >= 0.90
    assert meta.get("fraud_category") == "gift_card_fraud"
    assert display.get("status_label") == "High-Risk BEC / Gift-Card Fraud Detected"
    assert display.get("recommended_handling") in {"block", "review"}
    assert "block_request" in set(body.get("defender_actions") or [])
    reasons = " ".join(str(x) for x in (meta.get("bec_evidence_reasons") or []))
    assert "Gift-card purchase request" in reasons
    assert "PIN/card-number" in reasons


def test_benign_gift_card_mention_does_not_trigger_high_risk_category():
    result = _bec(
        "Gift card policy update",
        "We bought gift cards for the staff raffle. Please record receipts in the normal expense folder.",
    )

    assert result["fraud_category"] is None
    assert result["risk_floor"] is None
    assert result["bec_score"] == pytest.approx(0.0)


def test_payroll_direct_deposit_change_fraud_is_high_risk():
    result = _bec(
        "Urgent payroll update",
        "Payroll needs you to update direct deposit bank account details before the next pay cycle. Do not call; I am unavailable.",
        "HR Payroll <payroll@mobile-mail.example>",
    )

    assert result["fraud_category"] == "payroll_direct_deposit_change"
    assert result["bec_score"] >= 0.85
    assert result["risk_floor"] >= 0.75


def test_benign_payroll_policy_announcement_has_no_high_risk_floor():
    result = _bec(
        "Payroll policy announcement",
        "Payroll policy has been updated. Direct deposit changes must be made only through the HR portal after SSO login.",
        "HR <hr@corp.example>",
    )

    assert result["fraud_category"] is None
    assert result["risk_floor"] is None


def test_credential_phishing_with_suspicious_url_is_high_risk():
    result = _bec(
        "Password expires today",
        "Your mailbox password expires in 2 hours. Login now to verify your account: hxxps://secure-login-alerts[.]top/owa",
        "IT Desk <it@identity-check.example>",
    )

    assert result["fraud_category"] == "credential_harvesting"
    assert result["risk_floor"] >= 0.75
    assert "suspicious_url_or_domain" in result["matched_patterns"]


def test_invoice_payment_redirection_is_high_risk():
    result = _bec(
        "Updated remittance instructions",
        "Please update beneficiary account details for all pending invoices effective immediately. New bank confirmation letter attached. Do not call previous contacts.",
        "Accounts Payable <ap@vendor-mail.example>",
    )

    assert result["fraud_category"] in {"invoice_payment_redirection", "supplier_bank_change"}
    assert result["bec_score"] >= 0.85
    assert result["risk_floor"] >= 0.75


def test_missing_header_is_not_a_zero_risk_vote():
    uncertainty, components, missing = SpamDetectionService._compute_spam_uncertainty(
        spam_score=0.82,
        suspicious_threshold=0.50,
        ood_score=0.05,
        component_scores={
            "classical": 0.92,
            "heuristic": 0.86,
            "fraud_pattern": 0.98,
            "header": None,
        },
        component_weights={"classical": 0.20, "heuristic": 0.20, "fraud_pattern": 0.22},
        transformer_available=True,
        reputation_available=True,
        headers_available=False,
        fidelity_score=0.72,
    )

    assert missing == ["headers"]
    assert components["missing_component_uncertainty"] == pytest.approx(0.10)
    assert components["component_disagreement_uncertainty"] == pytest.approx(0.0)
    assert uncertainty < 0.40


def test_explicit_header_failure_is_active_evidence_not_missing():
    uncertainty, components, missing = SpamDetectionService._compute_spam_uncertainty(
        spam_score=0.82,
        suspicious_threshold=0.50,
        ood_score=0.05,
        component_scores={
            "classical": 0.92,
            "heuristic": 0.86,
            "fraud_pattern": 0.98,
            "header": 0.80,
        },
        component_weights={"classical": 0.20, "heuristic": 0.20, "fraud_pattern": 0.22, "header": 0.15},
        transformer_available=True,
        reputation_available=True,
        headers_available=True,
        fidelity_score=0.90,
    )

    assert missing == []
    assert components["missing_component_uncertainty"] == pytest.approx(0.0)
    assert components["component_disagreement_uncertainty"] == pytest.approx(0.0)
    assert uncertainty < 0.40


def test_evasion_normalisation_detects_obfuscated_login_url():
    result = _bec(
        "Security alert",
        "Your acc\u200b0unt is locked. l0gin now to verify identity: hxxps://credential-reset[.]top/session",
        "Security <security@identity-check.example>",
    )

    assert result["fraud_category"] == "credential_harvesting"
    assert result["risk_floor"] >= 0.75


def test_safe_newsletter_does_not_gain_fraud_floor():
    result = _bec(
        "Monthly benefits newsletter",
        "This newsletter explains how to avoid gift-card scams, password resets, and payroll fraud. No action is required.",
        "Comms <comms@corp.example>",
    )

    assert result["fraud_category"] is None
    assert result["risk_floor"] is None


def test_qr_payment_lure_routes_to_review_floor():
    result = _bec(
        "Final utility bill reminder",
        "Scan the QR code below to complete overdue bill payment and avoid disconnection. [QR CODE]",
    )

    assert result["fraud_category"] == "qr_phishing_or_image_lure"
    assert result["risk_floor"] >= 0.65
    assert result["recommended_handling_hint"] == "review"


def test_non_fraud_urgent_language_does_not_inflate_score():
    result = _bec(
        "Quick reminder",
        "Please join the board call immediately. The agenda is attached in the calendar invite.",
        "Assistant <assistant@corp.example>",
    )

    assert result["bec_score"] == pytest.approx(0.0)
    assert result["risk_floor"] is None
