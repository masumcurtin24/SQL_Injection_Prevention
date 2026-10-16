from __future__ import annotations

from backend.services.spam_detection_service import SpamDetectionService


def _service() -> SpamDetectionService:
    svc = object.__new__(SpamDetectionService)
    svc._blocklist_domains = set()
    svc._allowlist_domains = {
        "dhl.com",
        "dhl.com.au",
        "fedex.com",
        "ups.com",
        "usps.com",
        "auspost.com.au",
        "startrack.com.au",
        "royalmail.com",
        "dpd.com",
        "dpd.co.uk",
        "evri.com",
        "amazon.com",
        "corp.example",
    }
    svc._domain_reputation = {}
    svc._fraud_pattern_pack = {"version": "test", "patterns": []}
    return svc


def _courier(subject: str, body: str, sender: str = "Notice Desk <notice@example.net>") -> dict:
    svc = _service()
    text = f"{subject}\n{body}\n{sender}"
    url_indicators = svc._url_indicators(text)
    headers = svc._header_auth_indicators(
        headers=None,
        sender_email=sender,
        url_hosts=url_indicators.get("hosts"),
    )
    return svc.detect_courier_delivery_phishing_signals(
        message=body,
        sender=sender,
        subject=subject,
        url_indicators=url_indicators,
        header_indicators=headers,
    )


def _bec(subject: str, body: str, sender: str = "Notice Desk <notice@example.net>") -> dict:
    svc = _service()
    text = f"{subject}\n{body}\n{sender}"
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


def test_dhl_customs_fee_phishing_endpoint_is_high_risk(client):
    token = _admin_token(client)
    res = client.post(
        "/api/v1/analyze-spam/email",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "subject": "DHL parcel hold - Customs",
            "body_text": (
                "Your package cannot be delivered due to unpaid customs handling fee (AUD $2.80).\n"
                "Pay now: https://fast-post-tracking.net/customer/pay/37291\n"
                "If unpaid within 12 hours, parcel will be returned to sender."
            ),
            "sender_email": "Notice Desk <notice@fast-post-tracking.net>",
        },
    )

    assert res.status_code == 200, res.text
    body = res.json()
    spam = body.get("spam_classification") or {}
    meta = body.get("meta_features") or {}
    breakdown = body.get("score_breakdown") or {}
    display = body.get("decision_display") or {}

    assert float(spam.get("spam_score") or 0.0) >= 0.82
    assert meta.get("fraud_category") == "courier_customs_fee_phishing"
    assert meta.get("courier_category") == "courier_customs_fee_phishing"
    assert float(meta.get("courier_phishing_score") or 0.0) >= 0.90
    assert float(breakdown.get("courier_phishing") or 0.0) >= 0.90
    assert meta.get("brand_domain_mismatch") is True
    assert meta.get("suspicious_payment_link") is True
    assert display.get("status_label") in {
        "High-Risk Courier/Customs Fee Phishing Detected",
        "High-Risk Courier/Customs Fee Phishing - Review Required",
    }
    assert display.get("recommended_handling") in {"block", "review"}
    reasons = " ".join(str(item) for item in (meta.get("courier_evidence_reasons") or []))
    assert "customs fee payment lure" in reasons
    assert "not an official DHL domain" in reasons
    assert "return-to-sender" in reasons


def test_generic_redelivery_fee_with_suspicious_link_is_high_risk():
    result = _bec(
        "Parcel redelivery payment required",
        "Your parcel cannot be delivered. Pay the redelivery fee here: https://parcel-redelivery-fees.net/redelivery/pay",
        "Delivery Notice <notice@parcel-redelivery-fees.net>",
    )

    assert result["fraud_category"] in {"delivery_redelivery_fee_phishing", "package_hold_phishing"}
    assert result["risk_floor"] >= 0.75
    assert result["courier_phishing_score"] >= 0.80


def test_brand_domain_mismatch_detected_for_auspost_payment_lure():
    result = _courier(
        "AusPost delivery fee required",
        "Your package is waiting. Pay postage fee now at hxxps://auspost-redelivery[.]example/customer/pay.",
        "Australia Post <notice@auspost-redelivery.example>",
    )

    assert result["brand_domain_mismatch"] is True
    assert result["suspicious_payment_link"] is True
    assert result["risk_floor"] >= 0.82


def test_official_dhl_notification_without_payment_pressure_is_not_high_risk():
    result = _bec(
        "DHL shipment update",
        "Your package is scheduled for delivery tomorrow. Track it at https://www.dhl.com/en/express/tracking.html",
        "DHL <tracking@dhl.com>",
    )

    assert result["fraud_category"] is None
    assert result["risk_floor"] is None
    assert result["courier_official_domain_context"] is True


def test_shipping_notification_without_link_is_not_high_risk():
    result = _bec(
        "Package update",
        "Your package is scheduled for delivery tomorrow between 9 AM and 1 PM.",
        "Store <shipping@corp.example>",
    )

    assert result["fraud_category"] is None
    assert result["risk_floor"] is None


def test_training_awareness_text_is_not_classified_as_attack():
    result = _bec(
        "How to identify parcel delivery scams",
        "This training article explains DHL customs scams, redelivery fee lures, and why staff should use official websites.",
        "Security Awareness <training@corp.example>",
    )

    assert result["fraud_category"] is None
    assert result["risk_floor"] is None


def test_hxxp_and_bracketed_domain_obfuscation_is_detected():
    result = _courier(
        "DHL fee pending",
        "Final notice: pay customs handling fee at hxxps://dhl-pay[.]example/customer/pay within 12 hours.",
        "DHL <notice@dhl-pay.example>",
    )

    assert result["brand_domain_mismatch"] is True
    assert result["suspicious_payment_link"] is True
    assert result["risk_floor"] >= 0.82


def test_dhl_com_evil_net_is_not_treated_as_official():
    svc = _service()

    assert svc._host_matches_official_domain("dhl.com", {"dhl.com"}) is True
    assert svc._host_matches_official_domain("tracking.dhl.com", {"dhl.com"}) is True
    assert svc._host_matches_official_domain("dhl.com.evil.net", {"dhl.com"}) is False


def test_payment_path_evidence_is_reported():
    result = _courier(
        "DHL parcel fee",
        "Customs fee unpaid. Pay here: https://fast-post-tracking.net/customer/pay/37291",
        "DHL <notice@fast-post-tracking.net>",
    )

    assert result["suspicious_payment_link"] is True
    assert any("/customer/pay" in path for path in result["payment_paths"])
    assert "suspicious_payment_link" in result["matched_patterns"]


def test_newsletter_and_benign_parcel_update_do_not_gain_global_inflation():
    newsletter = _bec(
        "Monthly logistics newsletter",
        "Our warehouse newsletter covers package delivery trends and customer service updates. No action is required.",
        "Comms <comms@corp.example>",
    )
    parcel = _bec(
        "Order shipped",
        "Your order has shipped from our store. View order history in your normal customer account.",
        "Store <orders@corp.example>",
    )

    assert newsletter["bec_score"] == 0.0
    assert newsletter["risk_floor"] is None
    assert parcel["bec_score"] == 0.0
    assert parcel["risk_floor"] is None
