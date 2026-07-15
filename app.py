"""Chirp Hookbox: a secret-safe webhook inbox for Railway."""

from __future__ import annotations

import asyncio
import base64
import hmac
import json
import os
import shlex
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs
from uuid import uuid4

from chirp import (
    OOB,
    App,
    AppConfig,
    EventStream,
    Fragment,
    MutationResult,
    Page,
    Redirect,
    Request,
    Response,
    SSEEvent,
)
from chirp.middleware.csrf import CSRFConfig
from chirp.middleware.sessions import get_session
from chirp.middleware.stack import secure_stack

ROOT = Path(__file__).parent
MIGRATIONS = ROOT / "migrations"
MAX_BODY_BYTES = 128 * 1024
MAX_SEARCH_LENGTH = 120
MAX_RETENTION_DAYS = 90
DEFAULT_RETENTION_DAYS = 7
MASK = "[masked by Hookbox]"
SENSITIVE_HEADER_PARTS = (
    "authorization",
    "cookie",
    "credential",
    "secret",
    "signature",
    "token",
    "api-key",
    "apikey",
    "private-key",
)
REPLAY_OMIT_HEADERS = {
    "connection",
    "content-length",
    "cookie",
    "host",
    "transfer-encoding",
}


@dataclass(frozen=True, slots=True)
class Capture:
    id: str
    method: str
    path: str
    query_json: str
    headers_json: str
    content_type: str
    body_kind: str
    body_text: str
    body_bytes: int
    source_ip: str
    created_at: str


class LiveHub:
    """A bounded, one-worker fan-out hub with one queue per SSE subscriber."""

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[str]] = set()

    @asynccontextmanager
    async def subscribe(self) -> AsyncIterator[asyncio.Queue[str]]:
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=64)
        self._subscribers.add(queue)
        try:
            yield queue
        finally:
            self._subscribers.discard(queue)

    def publish(self, capture_id: str) -> None:
        for queue in tuple(self._subscribers):
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(capture_id)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def _positive_int(raw: str | None, default: int) -> int:
    try:
        return max(1, int(raw or default))
    except ValueError:
        return default


def _is_sensitive_header(name: str) -> bool:
    normalized = name.lower().replace("_", "-")
    return any(part in normalized for part in SENSITIVE_HEADER_PARTS)


def _masked_headers(request: Request) -> dict[str, str | list[str]]:
    masked: dict[str, str | list[str]] = {}
    for name in request.headers:
        values = request.headers.get_list(name)
        safe_values = [MASK if _is_sensitive_header(name) else value for value in values]
        masked[name] = safe_values[0] if len(safe_values) == 1 else safe_values
    return masked


def _body_for_storage(body: bytes, content_type: str) -> tuple[str, str]:
    if not body:
        return "empty", ""
    decoded = body.decode("utf-8", errors="replace")
    media_type = content_type.partition(";")[0].strip().lower()
    if media_type == "application/json" or media_type.endswith("+json"):
        try:
            return "json", json.dumps(json.loads(decoded), indent=2, ensure_ascii=False)
        except json.JSONDecodeError:
            return "malformed-json", decoded
    if media_type == "application/x-www-form-urlencoded":
        values = parse_qs(decoded, keep_blank_values=True)
        return "form", json.dumps(values, indent=2, ensure_ascii=False)
    if media_type.startswith("text/") or media_type in {
        "application/xml",
        "application/javascript",
    }:
        return "text", decoded
    return "binary-base64", base64.b64encode(body).decode("ascii")


def _json_object(raw: str) -> dict[str, Any]:
    value = json.loads(raw)
    return value if isinstance(value, dict) else {}


def _replay_curl(capture: Capture) -> str:
    headers = _json_object(capture.headers_json)
    commands = [
        "curl",
        "--request",
        capture.method,
        "--url",
        f"https://example.com{capture.path}",
    ]
    for name, raw_value in headers.items():
        if name.lower() in REPLAY_OMIT_HEADERS or _is_sensitive_header(name):
            continue
        values = raw_value if isinstance(raw_value, list) else [raw_value]
        commands.extend(f"--header {shlex.quote(f'{name}: {value}')}" for value in values)
    if capture.body_text and capture.body_kind != "binary-base64":
        commands.append(f"--data-raw {shlex.quote(capture.body_text)}")
    elif capture.body_kind == "binary-base64":
        commands.append("--data-binary @payload.bin")
    return " \\\n+  ".join(commands)


def create_app(
    database_url: str | None = None,
    *,
    admin_token: str | None = None,
    ingress_token: str | None = None,
    secret_key: str | None = None,
) -> App:
    """Build an isolated Hookbox application for production or tests."""

    config = AppConfig.from_env(
        template_dir=ROOT / "templates",
        worker_mode="async",
        workers=1,
        htmx=True,
        max_request_body_size=MAX_BODY_BYTES,
        sse_close_event="close",
    )
    if secret_key:
        config = replace(config, secret_key=secret_key)
    if not config.secret_key:
        config = replace(config, secret_key="hookbox-local-signing-key-with-enough-entropy")

    resolved_admin_token = admin_token or os.environ.get("HOOKBOX_ADMIN_TOKEN")
    resolved_ingress_token = ingress_token or os.environ.get("HOOKBOX_INGRESS_TOKEN")
    if not resolved_admin_token:
        if config.env != "development":
            raise RuntimeError("HOOKBOX_ADMIN_TOKEN is required outside development")
        resolved_admin_token = "hookbox-local-admin"
    if not resolved_ingress_token:
        if config.env != "development":
            raise RuntimeError("HOOKBOX_INGRESS_TOKEN is required outside development")
        resolved_ingress_token = "hookbox-local-ingress"

    resolved_database_url = database_url or os.environ.get(
        "DATABASE_URL", f"sqlite:///{ROOT / 'hookbox.db'}"
    )
    application = App(config, db=resolved_database_url, migrations=str(MIGRATIONS))
    ingress_path = f"/in/{resolved_ingress_token}"
    for middleware in secure_stack(
        application.config,
        csrf=CSRFConfig(exempt_paths=frozenset({ingress_path})),
    ):
        application.add_middleware(middleware)
    hub = LiveHub()

    def is_admin() -> bool:
        return get_session().get("hookbox_admin") is True

    async def retention_days() -> int:
        raw = await application.db.fetch_val(
            "SELECT value FROM hookbox_settings WHERE key = 'retention_days'"
        )
        return _positive_int(str(raw) if raw is not None else None, DEFAULT_RETENTION_DAYS)

    async def prune_expired() -> None:
        cutoff = datetime.now(UTC) - timedelta(days=await retention_days())
        await application.db.execute(
            "DELETE FROM captures WHERE created_at < ?",
            cutoff.isoformat(timespec="microseconds"),
        )

    @application.on_startup
    async def prepare_inbox() -> None:
        await application.db.execute(
            "INSERT INTO hookbox_settings (key, value) VALUES ('retention_days', ?) "
            "ON CONFLICT (key) DO NOTHING",
            str(DEFAULT_RETENTION_DAYS),
        )
        await prune_expired()

    async def list_captures(q: str = "") -> tuple[Capture, ...]:
        clean_query = q.strip()[:MAX_SEARCH_LENGTH]
        if clean_query:
            like = f"%{clean_query.lower()}%"
            return await application.db.fetch(
                Capture,
                "SELECT id, method, path, query_json, headers_json, content_type, "
                "body_kind, body_text, body_bytes, source_ip, created_at FROM captures "
                "WHERE LOWER(method || ' ' || path || ' ' || query_json || ' ' || "
                "headers_json || ' ' || body_text) LIKE ? "
                "ORDER BY created_at DESC, id DESC LIMIT 100",
                like,
            )
        return await application.db.fetch(
            Capture,
            "SELECT id, method, path, query_json, headers_json, content_type, "
            "body_kind, body_text, body_bytes, source_ip, created_at FROM captures "
            "ORDER BY created_at DESC, id DESC LIMIT 100",
        )

    async def fetch_capture(capture_id: str) -> Capture | None:
        return await application.db.fetch_one(
            Capture,
            "SELECT id, method, path, query_json, headers_json, content_type, "
            "body_kind, body_text, body_bytes, source_ip, created_at "
            "FROM captures WHERE id = ?",
            capture_id,
        )

    async def count_captures() -> int:
        return int(await application.db.fetch_val("SELECT COUNT(*) FROM captures") or 0)

    async def dashboard_context(*, q: str = "", notice: str = "") -> dict[str, Any]:
        admin = is_admin()
        return {
            "admin": admin,
            "captures": await list_captures(q) if admin else (),
            "capture_count": await count_captures() if admin else 0,
            "ingress_path": ingress_path if admin else "",
            "notice": notice,
            "q": q.strip()[:MAX_SEARCH_LENGTH],
            "retention_days": await retention_days() if admin else DEFAULT_RETENTION_DAYS,
        }

    async def dashboard_result(notice: str) -> MutationResult:
        current = await dashboard_context(notice=notice)
        return MutationResult(
            "/",
            Fragment("index.html", "dashboard", **current),
            Fragment("index.html", "notice", target="notice", **current),
            trigger="hookboxChanged",
        )

    @application.route("/", name="home")
    async def index(request: Request) -> Page | OOB:
        q = request.query.get("q", "") or ""
        current = await dashboard_context(q=q)
        if request.is_narrow_fragment:
            return OOB(
                Fragment("index.html", "dashboard", **current),
                Fragment("index.html", "stats", target="stats", **current),
            )
        return Page("index.html", "dashboard", page_block_name="page_root", **current)

    @application.route(ingress_path, methods=["POST", "PUT", "PATCH"], name="ingress")
    async def capture_request(request: Request) -> Response:
        supplied = request.path.rsplit("/", 1)[-1]
        if not hmac.compare_digest(supplied, resolved_ingress_token):
            return Response("Ingress token not accepted", status=404)
        body = await request.body()
        content_type = request.content_type or "application/octet-stream"
        body_kind, body_text = _body_for_storage(body, content_type)
        capture_id = uuid4().hex
        await prune_expired()
        await application.db.execute(
            "INSERT INTO captures "
            "(id, method, path, query_json, headers_json, content_type, body_kind, "
            "body_text, body_bytes, source_ip, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            capture_id,
            request.method,
            request.path,
            json.dumps(
                {name: request.query.get_list(name) for name in request.query},
                ensure_ascii=False,
                sort_keys=True,
            ),
            json.dumps(_masked_headers(request), ensure_ascii=False, sort_keys=True),
            content_type,
            body_kind,
            body_text,
            len(body),
            request.trusted_client_ip,
            _now(),
        )
        hub.publish(capture_id)
        return Response("Captured by Chirp Hookbox", status=202).with_header(
            "X-Hookbox-Request-ID", capture_id
        )

    @application.route("/admin/login", methods=["POST"], name="admin.login")
    async def admin_login(request: Request) -> MutationResult:
        form = await request.form()
        supplied = str(form.get("token") or "")
        if hmac.compare_digest(supplied, resolved_admin_token):
            get_session()["hookbox_admin"] = True
            return await dashboard_result("Inbox unlocked for this browser.")
        return await dashboard_result("That administrator token was not accepted.")

    @application.route("/admin/logout", methods=["POST"], name="admin.logout")
    async def admin_logout() -> MutationResult:
        get_session().pop("hookbox_admin", None)
        return await dashboard_result("Inbox locked.")

    @application.route("/admin/retention", methods=["POST"], name="admin.retention")
    async def update_retention(request: Request) -> MutationResult:
        if not is_admin():
            return await dashboard_result("Unlock the inbox before changing retention.")
        form = await request.form()
        days = _positive_int(str(form.get("days") or ""), DEFAULT_RETENTION_DAYS)
        if days > MAX_RETENTION_DAYS:
            return await dashboard_result(
                f"Choose a retention window between 1 and {MAX_RETENTION_DAYS} days."
            )
        await application.db.execute(
            "UPDATE hookbox_settings SET value = ? WHERE key = 'retention_days'",
            str(days),
        )
        await prune_expired()
        return await dashboard_result(f"Retention updated to {days} days.")

    @application.route(
        "/admin/captures/{capture_id}/delete",
        methods=["POST"],
        name="admin.delete",
    )
    async def delete_capture(capture_id: str) -> MutationResult:
        if not is_admin():
            return await dashboard_result("Unlock the inbox before deleting captures.")
        deleted = await application.db.execute("DELETE FROM captures WHERE id = ?", capture_id)
        return await dashboard_result(
            "Capture deleted." if deleted else "That capture is no longer in the inbox."
        )

    @application.route("/captures/{capture_id}", name="captures.detail")
    async def capture_detail(capture_id: str) -> Page | Redirect:
        if not is_admin():
            return Redirect("/")
        capture = await fetch_capture(capture_id)
        if capture is None:
            return Redirect("/")
        return Page(
            "detail.html",
            "detail",
            page_block_name="detail_page",
            capture=capture,
            headers=_json_object(capture.headers_json),
            query=_json_object(capture.query_json),
            replay_curl=_replay_curl(capture),
        )

    @application.route("/events", referenced=True, name="events")
    def events(request: Request) -> EventStream | Response:
        if not is_admin():
            return Response("Unlock the inbox to open its live feed", status=401)
        last_event_id = request.headers.get("last-event-id")

        async def replay_after(capture_id: str) -> tuple[Capture, ...]:
            cursor = await fetch_capture(capture_id)
            if cursor is None:
                return ()
            return await application.db.fetch(
                Capture,
                "SELECT id, method, path, query_json, headers_json, content_type, "
                "body_kind, body_text, body_bytes, source_ip, created_at FROM captures "
                "WHERE created_at > ? OR (created_at = ? AND id > ?) "
                "ORDER BY created_at ASC, id ASC LIMIT 100",
                cursor.created_at,
                cursor.created_at,
                cursor.id,
            )

        async def event_for(capture: Capture) -> SSEEvent:
            html = application.render(
                Fragment(
                    "index.html",
                    "live_update",
                    capture=capture,
                    capture_count=await count_captures(),
                )
            )
            return SSEEvent(data=html, event="message", id=capture.id)

        async def generate() -> AsyncIterator[SSEEvent]:
            seen: set[str] = set()
            async with hub.subscribe() as queue:
                if last_event_id:
                    for capture in await replay_after(last_event_id):
                        seen.add(capture.id)
                        yield await event_for(capture)
                while True:
                    capture_id = await queue.get()
                    if capture_id in seen:
                        continue
                    capture = await fetch_capture(capture_id)
                    if capture is not None:
                        seen.add(capture.id)
                        yield await event_for(capture)

        return EventStream(generate(), heartbeat_interval=15.0)

    @application.route("/styles.css", referenced=True)
    def styles() -> Response:
        return Response(
            (ROOT / "styles.css").read_text(encoding="utf-8"),
            content_type="text/css; charset=utf-8",
        )

    @application.route("/app.js", referenced=True)
    def script() -> Response:
        return Response(
            (ROOT / "app.js").read_text(encoding="utf-8"),
            content_type="text/javascript; charset=utf-8",
        )

    return application


app = create_app()


if __name__ == "__main__":
    app.run()
