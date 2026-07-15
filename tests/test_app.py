from __future__ import annotations

import asyncio
import re
from pathlib import Path
from urllib.parse import urlencode

import pytest
from chirp.data import DataError, MigrationError, QueryError
from chirp.testing import TestClient

import app as hookbox_app
from app import MAX_BODY_BYTES, create_app

pytestmark = pytest.mark.issue(809)
_CSRF_RE = re.compile(r'name="_csrf_token" value="([^"]+)"')


def _application(database: Path):
    return create_app(
        f"sqlite:///{database}",
        admin_token="test-admin-token",
        ingress_token="test-ingress-token",
        secret_key="test-signing-key-with-enough-entropy",
    )


def _cookie(response) -> str:
    value = response.header("set-cookie", "")
    assert value.startswith("chirp_session=")
    return value.split(";", 1)[0]


async def _unlock(client: TestClient) -> str:
    page = await client.get("/")
    token_match = _CSRF_RE.search(page.text)
    assert token_match is not None
    login = await client.post(
        "/admin/login",
        body=urlencode({"token": "test-admin-token", "_csrf_token": token_match.group(1)}).encode(),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": _cookie(page),
        },
    )
    assert login.status == 303
    return login.header("set-cookie", "").split(";", 1)[0]


async def _capture(
    client: TestClient,
    body: bytes = b'{"event":"invoice.paid"}',
    *,
    content_type: str = "application/json",
    method: str = "POST",
    extra_headers: dict[str, str] | None = None,
):
    response = await client.request(
        method,
        "/in/test-ingress-token?source=stripe",
        body=body,
        headers={"Content-Type": content_type, **(extra_headers or {})},
    )
    assert response.status == 202
    capture_id = response.header("x-hookbox-request-id")
    assert capture_id
    return capture_id


async def test_locked_page_health_readiness_and_assets(tmp_path: Path) -> None:
    app = _application(tmp_path / "locked.db")
    async with TestClient(app) as client:
        page = await client.get("/")
        health = await client.get("/health")
        ready = await client.get("/ready")
        css = await client.get("/styles.css")
        script = await client.get("/app.js")

    assert page.status == health.status == ready.status == css.status == script.status == 200
    assert "Catch the signal" in page.text
    assert "test-ingress-token" not in page.text
    assert "--violet:" in css.text
    assert "navigator.clipboard" in script.text


async def test_unlock_rejects_wrong_token_and_accepts_admin(tmp_path: Path) -> None:
    app = _application(tmp_path / "login.db")
    async with TestClient(app) as client:
        page = await client.get("/")
        match = _CSRF_RE.search(page.text)
        assert match is not None
        cookie = _cookie(page)
        rejected = await client.post(
            "/admin/login",
            body=urlencode({"token": "wrong", "_csrf_token": match.group(1)}).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
        )
        admin_cookie = await _unlock(client)
        dashboard = await client.get("/", headers={"Cookie": admin_cookie})

    assert rejected.status == 303
    assert "private ingress URL" in dashboard.text
    assert "/in/test-ingress-token" in dashboard.text
    assert 'sse-connect="/events"' in dashboard.text


async def test_unlock_and_logout_forms_use_full_page_navigation(tmp_path: Path) -> None:
    app = _application(tmp_path / "session-navigation.db")
    async with TestClient(app) as client:
        page = await client.get("/")
        assert '<form class="unlock" action="/admin/login" method="post">' in page.text
        assert 'action="/admin/login" method="post" hx-post' not in page.text
        admin_cookie = await _unlock(client)
        dashboard = await client.get("/", headers={"Cookie": admin_cookie})

    assert '<form action="/admin/logout" method="post">' in dashboard.text
    assert 'action="/admin/logout" method="post" hx-post' not in dashboard.text


async def test_json_capture_masks_credentials_before_persistence(tmp_path: Path) -> None:
    app = _application(tmp_path / "json.db")
    async with TestClient(app) as client:
        admin_cookie = await _unlock(client)
        capture_id = await _capture(
            client,
            extra_headers={
                "Authorization": "Bearer raw-secret",
                "X-Webhook-Signature": "signature-secret",
                "X-Trace": "trace-safe",
            },
        )
        detail = await client.get(f"/captures/{capture_id}", headers={"Cookie": admin_cookie})

    assert detail.status == 200
    assert "invoice.paid" in detail.text
    assert "[masked by Hookbox]" in detail.text
    assert "raw-secret" not in detail.text
    assert "signature-secret" not in detail.text
    assert "trace-safe" in detail.text
    assert "source" in detail.text and "stripe" in detail.text


@pytest.mark.parametrize(
    ("body", "content_type", "expected"),
    [
        (b"name=Ada&active=true", "application/x-www-form-urlencoded", "form"),
        (b"hello webhook", "text/plain", "text"),
        (b"", "text/plain", "empty"),
        (b'{"broken":', "application/json", "malformed-json"),
        (b"\x00\xff", "application/octet-stream", "binary-base64"),
    ],
)
async def test_body_types_are_inspectable(
    tmp_path: Path, body: bytes, content_type: str, expected: str
) -> None:
    app = _application(tmp_path / f"{expected}.db")
    async with TestClient(app) as client:
        admin_cookie = await _unlock(client)
        capture_id = await _capture(client, body, content_type=content_type)
        detail = await client.get(f"/captures/{capture_id}", headers={"Cookie": admin_cookie})

    assert expected in detail.text


async def test_invalid_ingress_and_oversized_body_fail_without_storage(tmp_path: Path) -> None:
    app = _application(tmp_path / "limits.db")
    async with TestClient(app) as client:
        invalid = await client.post("/in/wrong", body=b"no")
        oversized = await client.post(
            "/in/test-ingress-token",
            body=b"x" * (MAX_BODY_BYTES + 1),
            headers={"Content-Type": "text/plain"},
        )
        admin_cookie = await _unlock(client)
        page = await client.get("/", headers={"Cookie": admin_cookie})

    assert invalid.status == 403
    assert oversized.status == 413
    assert "0</strong>" in page.text


async def test_xss_shaped_payload_is_escaped(tmp_path: Path) -> None:
    app = _application(tmp_path / "xss.db")
    async with TestClient(app) as client:
        admin_cookie = await _unlock(client)
        capture_id = await _capture(
            client,
            b"<script>window.pwned=true</script>",
            content_type="text/html",
        )
        detail = await client.get(f"/captures/{capture_id}", headers={"Cookie": admin_cookie})

    assert "&lt;script&gt;window.pwned=true&lt;/script&gt;" in detail.text
    assert "<script>window.pwned=true</script>" not in detail.text


async def test_search_htmx_and_delete_plain_html(tmp_path: Path) -> None:
    app = _application(tmp_path / "search.db")
    async with TestClient(app) as client:
        admin_cookie = await _unlock(client)
        capture_id = await _capture(client, b"needle", content_type="text/plain")
        await _capture(client, b"haystack", content_type="text/plain", method="PATCH")
        search = await client.get(
            "/?q=needle",
            headers={"Cookie": admin_cookie, "HX-Request": "true", "HX-Target": "dashboard"},
        )
        page = await client.get("/", headers={"Cookie": admin_cookie})
        match = _CSRF_RE.search(page.text)
        assert match is not None
        deleted = await client.post(
            f"/admin/captures/{capture_id}/delete",
            body=urlencode({"_csrf_token": match.group(1)}).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded", "Cookie": admin_cookie},
        )

    assert "needle" in search.text
    assert "PATCH" not in search.text
    assert deleted.status == 303


async def test_sse_reconnect_replays_only_the_gap(tmp_path: Path) -> None:
    app = _application(tmp_path / "sse.db")
    async with TestClient(app) as client:
        admin_cookie = await _unlock(client)
        first_id = await _capture(client, b"first", content_type="text/plain")
        second_id = await _capture(client, b"second", content_type="text/plain")
        replay = await client.sse(
            "/events",
            headers={"Cookie": admin_cookie, "Last-Event-ID": first_id},
            max_events=1,
        )

    assert replay.events[0].id == second_id
    assert replay.events[0].event == "message"
    assert "hx-swap-oob" in replay.events[0].data


async def test_concurrent_arrivals_are_all_durable(tmp_path: Path) -> None:
    app = _application(tmp_path / "concurrent.db")
    async with TestClient(app) as client:
        ids = await asyncio.gather(
            *(
                _capture(client, f"event-{index}".encode(), content_type="text/plain")
                for index in range(12)
            )
        )
        admin_cookie = await _unlock(client)
        page = await client.get("/", headers={"Cookie": admin_cookie})

    assert len(set(ids)) == 12
    assert "12</strong>" in page.text


async def test_retention_setting_and_restart_persistence(tmp_path: Path) -> None:
    database = tmp_path / "persistent.db"
    first_app = _application(database)
    async with TestClient(first_app) as client:
        admin_cookie = await _unlock(client)
        capture_id = await _capture(client, b"survives", content_type="text/plain")
        page = await client.get("/", headers={"Cookie": admin_cookie})
        match = _CSRF_RE.search(page.text)
        assert match is not None
        updated = await client.post(
            "/admin/retention",
            body=urlencode({"days": "30", "_csrf_token": match.group(1)}).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded", "Cookie": admin_cookie},
        )
        assert updated.status == 303

    second_app = _application(database)
    async with TestClient(second_app) as client:
        admin_cookie = await _unlock(client)
        detail = await client.get(f"/captures/{capture_id}", headers={"Cookie": admin_cookie})
        page = await client.get("/", headers={"Cookie": admin_cookie})

    assert "survives" in detail.text
    assert 'value="30"' in page.text


async def test_database_unavailable_at_startup_is_actionable() -> None:
    app = create_app(
        "postgresql://postgres:postgres@127.0.0.1:1/railway",
        admin_token="test-admin-token",
        ingress_token="test-ingress-token",
        secret_key="test-signing-key-with-enough-entropy",
    )
    with pytest.raises(DataError, match=r"could not connect to 127\.0\.0\.1:1"):
        async with TestClient(app):
            pass


async def test_migration_failure_names_the_broken_migration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    (migrations / "001_broken.sql").write_text("CREATE TABL broken (", encoding="utf-8")
    monkeypatch.setattr(hookbox_app, "MIGRATIONS", migrations)
    app = _application(tmp_path / "broken.db")
    with pytest.raises(MigrationError, match="Migration 001_broken failed"):
        async with TestClient(app):
            pass


async def test_schema_mismatch_fails_loud(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    (migrations / "001_wrong.sql").write_text(
        "CREATE TABLE captures (id TEXT PRIMARY KEY); "
        "CREATE TABLE hookbox_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
        encoding="utf-8",
    )
    monkeypatch.setattr(hookbox_app, "MIGRATIONS", migrations)
    app = _application(tmp_path / "wrong.db")
    with pytest.raises(QueryError, match="no such column: created_at"):
        async with TestClient(app):
            pass


def test_app_contracts_pass(tmp_path: Path) -> None:
    app = _application(tmp_path / "contracts.db")
    assert app.config.workers == 1
    assert app.config.max_request_body_size == MAX_BODY_BYTES
    app.freeze()
    assert any(check.name == "database" for check in app._mutable_state.health_checks)
    app.check()
