"""Safe database URL formatting for operational logs."""

from __future__ import annotations

import re

from sqlalchemy.engine import URL, make_url


_URL_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")


def sanitize_database_url(value: str | None) -> str:
    """Return a useful URL summary without credentials or query parameters.

    Database URLs can carry secrets both in user-info (``user:password@``) and
    in driver-specific query parameters. Rebuilding the URL from only its
    non-secret routing fields is safer than trying to maintain a list of every
    possible secret query key.
    """

    raw_value = str(value or "").strip()
    if not raw_value:
        return "<not set>"

    try:
        parsed = make_url(raw_value)
        safe_url = URL.create(
            drivername=parsed.drivername,
            host=parsed.host,
            port=parsed.port,
            database=parsed.database,
        )
        return safe_url.render_as_string(hide_password=True)
    except Exception:
        # Never echo an unparseable value: it may still contain credentials.
        scheme_match = _URL_SCHEME_RE.match(raw_value)
        if scheme_match:
            return f"{scheme_match.group(1)}://<redacted>"
        return "<redacted database URL>"
