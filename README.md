# Chirp Hookbox

A focused self-hosted webhook inbox and request bin powered by
[Chirp](https://github.com/lbliii/chirp) and PostgreSQL. It is designed for a
zero-input Railway deployment: the template provisions PostgreSQL, generates
separate administrator, ingress, and signing secrets, runs migrations before
promotion, and checks database readiness.

Hookbox accepts bounded POST, PUT, and PATCH requests at a tokenized ingress
URL. The private dashboard provides searchable request summaries and detail
views for method, path, query parameters, headers, source, content type, and
JSON/form/text bodies. New requests arrive through Chirp SSE/OOB updates, and
each capture includes a safe replay-as-cURL command.

Credential-shaped headers are irreversibly masked before persistence. Request
bodies are limited to 128 KiB. Captured HTML is always rendered as escaped text.

## Run locally

Python 3.14 and [uv](https://docs.astral.sh/uv/) are required.

```bash
uv sync --frozen
uv run python app.py
```

The local app uses `hookbox.db`. Open <http://127.0.0.1:8000> and use:

```text
HOOKBOX_ADMIN_TOKEN=hookbox-local-admin
HOOKBOX_INGRESS_TOKEN=hookbox-local-ingress
```

Send a capture with:

```bash
curl -X POST http://127.0.0.1:8000/in/hookbox-local-ingress \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer this-will-be-masked' \
  -d '{"event":"invoice.paid"}'
```

## Deploy on Railway

The Railway template intentionally creates only:

- one Chirp web service pinned to one async worker;
- one Railway-managed PostgreSQL service;
- generated signing, administrator, and ingress secrets;
- `chirp migrate` as the pre-deploy command;
- `/ready` as the deployment healthcheck.

After deployment, retrieve `HOOKBOX_ADMIN_TOKEN` from the web service variables,
unlock the dashboard, and copy the ingress path shown there. The write token is
embedded in that path and should be treated as a credential.

## Verify

```bash
uv run ruff check .
uv run ruff format . --check
uv run pytest -q
```

Acceptance #809 is covered locally by `@pytest.mark.issue(809)` and completed by
the catalog's live deployment, restart, update, rollback, shutdown, and ejection
receipts.

## Data and rollback boundary

Migrations are forward-only and must remain compatible with the previous
application release. A Railway application rollback does not roll back
PostgreSQL data. Verify a database backup before any future destructive schema
change. Retention is applied during startup and before each new capture.

## Support

Report Hookbox problems in this repository. Chirp framework problems belong in
the [Chirp issue tracker](https://github.com/lbliii/chirp/issues).

## License

MIT
