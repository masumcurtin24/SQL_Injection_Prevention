def test_app_startup_health_and_auth_gate(client):
    live = client.get("/health/live")
    assert live.status_code == 200
    assert (live.json() or {}).get("status") == "alive"

    health = client.get("/health")
    assert health.status_code == 200
    payload = health.json() or {}
    assert payload.get("ready") is True
    assert payload.get("error") in (None, "")

    ready = client.get("/health/ready")
    assert ready.status_code == 200
    assert (ready.json() or {}).get("status") == "ready"

    me = client.get("/api/v1/auth/me")
    assert me.status_code == 401
