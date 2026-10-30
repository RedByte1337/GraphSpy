# Repository instructions

## Project

GraphSpy is a cross-platform Python 3.10+ Flask application for operating against Entra ID and Microsoft 365 with OAuth tokens. It calls Microsoft APIs directly through backend HTTP helpers rather than Microsoft SDKs.

Read [`DEVELOPMENT.md`](DEVELOPMENT.md) when changing architecture, request handling, Microsoft API behavior, tokens, schema, proxying, retries, logging, UI integration, or dependencies. For focused changes, read only the relevant section and its linked source files.

Before preparing a commit, pull the current branch with `git pull --rebase --autostash`; never commit against stale remote history. Then follow [`CONTRIBUTING.md`](CONTRIBUTING.md), including its reference to [`AI_POLICY.md`](AI_POLICY.md).

## Core contracts

- Keep Flask API routes thin; Microsoft protocol and product workflows belong in `core`, while SQLite behavior belongs in `db`.
- Send Microsoft API calls from the backend through `src/graphspy/core/requests_.py`; do not add Microsoft SDKs or browser-side outbound API logic.
- Update both `src/graphspy/db/schema.py` and `src/graphspy/db/migrations.py` for schema changes.
- Preserve the intentional proxied `verify=False`, HTTP 429 retry, logging, and error-handling behavior unless the task changes it.
- Use Python 3.10-compatible typing and the repository's explicit import-section comments; keep code portable across Linux, Windows, and macOS.
- Prefer Bootstrap and jQuery patterns already used by the UI, and route output through the existing templates and static assets.
- Update `pyproject.toml` and `uv.lock` together when dependencies change.

## Verification

Validate the affected request or startup path. For database changes, verify both fresh initialization and migration behavior. This repository has no automated test suite, so report the source-level and runtime checks performed.
