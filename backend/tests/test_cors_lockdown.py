def test_cors_lockdown_disallowed_origin(client):
    r = client.get("/health", headers={"Origin": "http://evil.com"})
    assert r.status_code == 200, r.text
    assert r.headers.get("access-control-allow-origin") is None


def test_cors_lockdown_allowed_origin_and_preflight(client):
    allowed = "http://localhost:5173"

    r = client.get("/health", headers={"Origin": allowed})
    assert r.status_code == 200, r.text
    assert r.headers.get("access-control-allow-origin") == allowed
    assert r.headers.get("access-control-allow-credentials") is None

    pre = client.options(
        "/api/v1/auth/login",
        headers={
            "Origin": allowed,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,authorization",
        },
    )
    assert pre.status_code in (200, 204), pre.text
    assert pre.headers.get("access-control-allow-origin") == allowed
    assert pre.headers.get("access-control-allow-credentials") is None

