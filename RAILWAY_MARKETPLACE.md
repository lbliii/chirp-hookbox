# Deploy and Host a Webhook Inbox with Chirp Hookbox

Launch a polished self-hosted webhook inbox and request bin powered by Chirp and PostgreSQL. Send POST, PUT, or PATCH requests to a tokenized ingress URL and inspect each arrival in a private, searchable dashboard with live updates.

## About Hosting

The template provisions one Chirp web service and one Railway-managed PostgreSQL service. Railway generates separate application, administrator, and ingress secrets, supplies the database URL, runs migrations before each release is promoted, and checks `/ready` before routing traffic.

Credential-shaped headers are masked before persistence, bodies are bounded to 128 KiB, and captured HTML remains escaped text. PostgreSQL owns durable captures and retention settings. Redis and external SaaS accounts are not required for the single-replica product.

## Why Deploy

- Inspect JSON, form, text, empty, malformed, and binary webhook payloads.
- Watch new requests arrive through server-rendered SSE/OOB updates.
- Search method, path, query, headers, and bodies without a separate SPA or API.
- Copy a safe replay-as-cURL command that omits masked credentials.
- Keep a simple, ejectable app-plus-PostgreSQL topology.

## Common Use Cases

- Developing and debugging webhook integrations
- Inspecting payment, CI, Git hosting, and automation callbacks
- Replacing temporary third-party request bins with a private deployment
- Teaching server-rendered realtime patterns with Chirp and HTMX

## Dependencies

- A Chirp web service built from `lbliii/chirp-hookbox`
- Railway PostgreSQL with a persistent volume
- Python 3.14 and dependencies locked in the repository

No Redis service or external account is required.

Framework documentation: https://lbliii.github.io/chirp/

Source and support: https://github.com/lbliii/chirp-hookbox
