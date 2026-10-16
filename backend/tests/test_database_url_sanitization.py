from backend.core.database_url import sanitize_database_url


def test_sanitize_database_url_removes_userinfo_and_query_secrets():
    raw = (
        "postgresql+psycopg://db-user:p%40ssword@db.example.com:5432/app_db"
        "?sslmode=require&sslpassword=another-secret&access_token=token-secret"
    )

    sanitized = sanitize_database_url(raw)

    assert sanitized == "postgresql+psycopg://db.example.com:5432/app_db"
    for secret in ("db-user", "p%40ssword", "another-secret", "token-secret"):
        assert secret not in sanitized


def test_sanitize_database_url_keeps_safe_sqlite_location_without_query():
    sanitized = sanitize_database_url("sqlite:///./runtime/app.db?password=secret")

    assert sanitized == "sqlite:///./runtime/app.db"
    assert "secret" not in sanitized


def test_sanitize_database_url_never_echoes_unparseable_input():
    raw = "not a valid url containing password=hunter2"

    sanitized = sanitize_database_url(raw)

    assert sanitized == "<redacted database URL>"
    assert "hunter2" not in sanitized
