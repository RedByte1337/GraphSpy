# GraphSpy: AI Engineering Guide

This file is the canonical AI guidance for this repository. For what GraphSpy is and what it does, see [README.md](README.md).

## Runtime and Tooling

* Python baseline is 3.10+ (see [pyproject.toml](pyproject.toml): `requires-python = ">=3.10,<4.0"`).
* Use `uv` for dependency and environment management in this repo.
* GraphSpy is a Flask web application served by Waitress in normal mode and Flask's development server only when `--dev` is explicitly used.

## Read Order

1. [README.md](README.md) — product capabilities, operator workflows, and feature surface.
2. [DEVELOPMENT.md](DEVELOPMENT.md) — architecture, request lifecycle, schema model, and extension guidance (source of truth).
3. [src/graphspy/cli.py](src/graphspy/cli.py) — entry point, app dir resolution, logging, DB bootstrap, server startup.
4. [src/graphspy/app.py](src/graphspy/app.py) — Flask app factory, blueprint registration, error handling.
5. [src/graphspy/db/schema.py](src/graphspy/db/schema.py) and [src/graphspy/db/migrations.py](src/graphspy/db/migrations.py) — SQLite schema and migration model.
6. Representative core/API modules for the feature you are changing.

## Architecture Summary

GraphSpy has four main layers:

1. **CLI/bootstrap** — [src/graphspy/cli.py](src/graphspy/cli.py) handles startup, argument parsing, DB bootstrap, and server launch.
2. **Web/app composition** — [src/graphspy/app.py](src/graphspy/app.py) creates the Flask app and registers API and page blueprints.
3. **API layer** — modules under [src/graphspy/api](src/graphspy/api) stay thin: parse input, delegate to core/DB helpers, return responses.
4. **Core and data layer** — modules under [src/graphspy/core](src/graphspy/core) implement the product workflows (see [README.md](README.md)). [src/graphspy/db](src/graphspy/db) handles SQLite access, schema, and migrations through [src/graphspy/db/connection.py](src/graphspy/db/connection.py).

See [DEVELOPMENT.md](DEVELOPMENT.md) for full design principles, feature boundaries, and request lifecycle details.

## Python Rules

1. **Imports** — standard library, third-party, local. Explicit section comments: `# Built-in imports`, `# Third party library imports`, `# Local library imports`.
2. **Typing** — modern 3.10+ syntax (`X | Y`, `X | None`). Keep return type annotations honest.
3. **Error handling** — avoid broad `except Exception`. Use Loguru throughout. Use `logger.exception(...)` when stack traces matter. Use `AppError` for application-level errors that should flow through Flask handlers.
4. **Code hygiene** — minimal diffs, no style churn in files you touch, comments only where the why is non-obvious.

## Microsoft Documentation

Use Microsoft documentation when behavior depends on service semantics, permissions, or protocol details.

* Microsoft Graph overview: https://learn.microsoft.com/graph/overview
* Microsoft Graph REST API v1.0 reference: https://learn.microsoft.com/graph/api/overview?view=graph-rest-1.0
* Microsoft Graph throttling guidance: https://learn.microsoft.com/graph/throttling
* Microsoft identity platform OAuth 2.0 device authorization grant: https://learn.microsoft.com/entra/identity-platform/v2-oauth2-device-code
* Microsoft Graph authentication and permissions overview: https://learn.microsoft.com/graph/auth/auth-concepts
* Microsoft Graph user resource: https://learn.microsoft.com/graph/api/resources/user?view=graph-rest-1.0
* Microsoft Graph driveItem resource: https://learn.microsoft.com/graph/api/resources/driveitem?view=graph-rest-1.0
* Microsoft Graph site resource: https://learn.microsoft.com/graph/api/resources/site?view=graph-rest-1.0
* Microsoft Graph authentication methods API overview: https://learn.microsoft.com/graph/api/resources/authenticationmethods-overview?view=graph-rest-1.0
* Microsoft Graph teams/conversation resources: https://learn.microsoft.com/graph/api/resources/teams-api-overview?view=graph-rest-1.0

## Testing and Validation

* Validate syntax or startup surface for the slice you changed.
* For dependency changes, keep [pyproject.toml](pyproject.toml) and [uv.lock](uv.lock) synchronized.
* For DB changes, validate both fresh initialization and migration behavior.
* For API changes, prefer a focused request-path or startup validation.

## Definition of Done

A change is complete only if all are true:

1. The change respects the existing CLI/app/API/core/DB layering.
2. Any schema change includes migration handling.
3. Proxy, logging, and error-handling behavior remain intentional.
4. Python 3.10+ compatibility is preserved.
5. Relevant Microsoft API semantics were checked when behavior depends on them.
6. [pyproject.toml](pyproject.toml) and [uv.lock](uv.lock) remain consistent when dependencies change.
