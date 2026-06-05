# GraphSpy: AI Engineering Guide

This file is the canonical AI guidance for this repository.

## Runtime and Tooling

- Python baseline is 3.10+ (see [pyproject.toml](pyproject.toml): `requires-python = ">=3.10,<4.0"`).
- Use `uv` for dependency and environment management in this repo.
- GraphSpy is a Flask web application served by Waitress in normal mode and Flask's development server only when `--dev` is explicitly used.

## Read Order

1. [README.md](README.md) - product capabilities, operator workflows, and feature surface.
2. [DEVELOPMENT.md](DEVELOPMENT.md) - architecture, request lifecycle, schema model, and extension guidance (source of truth).
3. [src/graphspy/cli.py](src/graphspy/cli.py) - entry point, app dir resolution, logging, DB bootstrap, server startup.
4. [src/graphspy/app.py](src/graphspy/app.py) - Flask app factory, blueprint registration, error handling.
5. [src/graphspy/db/schema.py](src/graphspy/db/schema.py) and [src/graphspy/db/migrations.py](src/graphspy/db/migrations.py) - SQLite schema and migration model.
6. Representative core/API modules for the feature you are changing.

## Architecture Summary

GraphSpy is a browser-based Entra ID / M365 post-exploitation application with four main layers:

1. CLI/bootstrap
- [src/graphspy/cli.py](src/graphspy/cli.py) parses arguments, initializes logging, resolves the database path, creates the Flask app, and starts Waitress or the dev server.

2. Web/app composition
- [src/graphspy/app.py](src/graphspy/app.py) creates the Flask app and registers the API and page blueprints.
- [src/graphspy/web/pages.py](src/graphspy/web/pages.py) is route-to-template wiring only.
- Templates and static assets live under [src/graphspy/web/templates](src/graphspy/web/templates) and [src/graphspy/web/static](src/graphspy/web/static).

3. API layer
- Files in [src/graphspy/api](src/graphspy/api) expose HTTP endpoints and should stay thin.
- API modules should validate request input, call core/db helpers, and return responses. They should not accumulate protocol-heavy business logic.

4. Core and data layer
- Files in [src/graphspy/core](src/graphspy/core) implement the M365 / Entra workflows: tokens, device codes, MFA, PRT, WinHello, Teams, generic requests.
- Files in [src/graphspy/db](src/graphspy/db) handle SQLite access, schema initialization, and migrations.
- [src/graphspy/db/connection.py](src/graphspy/db/connection.py) is the central DB access module and uses Flask `g` for request-scoped connections.

## Source Map (Start Here)

- Entry point: [src/graphspy/cli.py](src/graphspy/cli.py)
- App factory: [src/graphspy/app.py](src/graphspy/app.py)
- Logging setup: [src/graphspy/logbook.py](src/graphspy/logbook.py)
- API helpers: [src/graphspy/api/helpers.py](src/graphspy/api/helpers.py)
- Generic request wrapper: [src/graphspy/core/requests_.py](src/graphspy/core/requests_.py)
- Token-related logic: [src/graphspy/core/tokens.py](src/graphspy/core/tokens.py)
- Device registration logic: [src/graphspy/core/device.py](src/graphspy/core/device.py)
- Device code logic: [src/graphspy/core/device_codes.py](src/graphspy/core/device_codes.py)
- PRT logic: [src/graphspy/core/prt.py](src/graphspy/core/prt.py)
- MFA logic: [src/graphspy/core/mfa.py](src/graphspy/core/mfa.py)
- WinHello logic: [src/graphspy/core/winhello.py](src/graphspy/core/winhello.py)
- Schema bootstrap: [src/graphspy/db/schema.py](src/graphspy/db/schema.py)
- Schema migrations: [src/graphspy/db/migrations.py](src/graphspy/db/migrations.py)

## Design Principles (Strict)

This section is a strict summary. Detailed rationale and architecture notes live in [DEVELOPMENT.md](DEVELOPMENT.md).
If this file and [DEVELOPMENT.md](DEVELOPMENT.md) ever diverge, follow [DEVELOPMENT.md](DEVELOPMENT.md) for architecture and design decisions.

1. SRP
- Keep page routes, API handlers, core logic, and DB access in separate layers.
- Do not move protocol or token-processing logic into template/page modules.
- Keep API blueprints thin and core modules focused on one workflow.

2. Composition over sprawl
- Reuse the existing modules in [src/graphspy/core](src/graphspy/core), [src/graphspy/api](src/graphspy/api), and [src/graphspy/db](src/graphspy/db) instead of duplicating logic.
- Prefer small helper functions over large mixed-purpose request handlers.

3. Open for extension
- Add new HTTP functionality by introducing or extending an API module plus matching template/page route only when needed.
- If a change affects stored data, update both [src/graphspy/db/schema.py](src/graphspy/db/schema.py) and [src/graphspy/db/migrations.py](src/graphspy/db/migrations.py) consistently.

4. Thin API, thick core
- API modules should parse request/form input and delegate to core logic.
- Core modules should own request building, token handling, Microsoft API interaction, and business rules.

5. Fail fast and observable
- Prefer raising or returning explicit errors over silent fallback behavior.
- Keep request logging and error reporting consistent with [src/graphspy/logbook.py](src/graphspy/logbook.py) and [src/graphspy/core/errors.py](src/graphspy/core/errors.py).

## Python Rules

1. Imports
- Keep imports grouped as standard library, third-party, local.
- Add explicit section comments for import groups: `# Built-in imports`, `# External library imports` or `# Third party library imports`, `# Local library imports`.
- Prefer module imports when importing utility-style modules.

2. Typing and modern Python
- Use modern Python typing syntax compatible with 3.10+ such as `X | Y` and `X | None`.
- Keep return types honest where annotations already exist.
- Do not introduce unnecessary compatibility shims for pre-3.10 Python.

3. Error handling and logging
- Avoid broad `except Exception` unless you are translating or intentionally degrading behavior.
- Use Loguru consistently.
- Use `logger.exception(...)` inside exception handlers when traceback context is important.
- Use `AppError` for application-level errors that should be surfaced cleanly through Flask handlers.

4. Code hygiene
- Prefer minimal diffs.
- Avoid broad style churn in files you touch.
- Keep comments concise and only where they add actual context.

## Request and Proxy Conventions

- Centralize outbound HTTP behavior through [src/graphspy/core/requests_.py](src/graphspy/core/requests_.py) when applicable.
- Preserve the current proxy model: when a proxy is configured, certificate verification may be disabled intentionally for operator workflows. Do not "fix" this without an explicit product decision.
- Preserve retry/throttling behavior for Microsoft API calls unless the change specifically targets that logic.

## Database Rules

- SQLite schema changes require matching migration coverage.
- Do not edit the active schema in [src/graphspy/db/schema.py](src/graphspy/db/schema.py) without also considering upgrade paths in [src/graphspy/db/migrations.py](src/graphspy/db/migrations.py).
- Keep DB access routed through [src/graphspy/db/connection.py](src/graphspy/db/connection.py) instead of ad-hoc sqlite connections spread through the app.

## Feature-Specific Guidance

When touching these areas, start here:

- Access/refresh tokens: [src/graphspy/api/access_tokens.py](src/graphspy/api/access_tokens.py), [src/graphspy/api/refresh_tokens.py](src/graphspy/api/refresh_tokens.py), [src/graphspy/core/tokens.py](src/graphspy/core/tokens.py)
- Device code flows: [src/graphspy/api/device_codes.py](src/graphspy/api/device_codes.py), [src/graphspy/core/device_codes.py](src/graphspy/core/device_codes.py)
- Device registration / certificates: [src/graphspy/api/devices.py](src/graphspy/api/devices.py), [src/graphspy/core/device.py](src/graphspy/core/device.py)
- MFA: [src/graphspy/api/mfa.py](src/graphspy/api/mfa.py), [src/graphspy/core/mfa.py](src/graphspy/core/mfa.py)
- PRT / WinHello: [src/graphspy/core/prt.py](src/graphspy/core/prt.py), [src/graphspy/core/winhello.py](src/graphspy/core/winhello.py)
- Generic Graph/custom requests: [src/graphspy/api/requests_.py](src/graphspy/api/requests_.py), [src/graphspy/core/requests_.py](src/graphspy/core/requests_.py)
- Entra listings/details: [src/graphspy/api/entra.py](src/graphspy/api/entra.py)
- Teams: [src/graphspy/api/teams.py](src/graphspy/api/teams.py), [src/graphspy/core/teams.py](src/graphspy/core/teams.py)

## Microsoft Documentation

Use Microsoft documentation when behavior depends on service semantics, permissions, or protocol details.

- Microsoft Graph overview: https://learn.microsoft.com/graph/overview
- Microsoft Graph REST API v1.0 reference: https://learn.microsoft.com/graph/api/overview?view=graph-rest-1.0
- Microsoft Graph throttling guidance: https://learn.microsoft.com/graph/throttling
- Microsoft identity platform OAuth 2.0 device authorization grant: https://learn.microsoft.com/entra/identity-platform/v2-oauth2-device-code
- Microsoft Graph authentication and permissions overview: https://learn.microsoft.com/graph/auth/auth-concepts
- Microsoft Graph user resource: https://learn.microsoft.com/graph/api/resources/user?view=graph-rest-1.0
- Microsoft Graph driveItem resource: https://learn.microsoft.com/graph/api/resources/driveitem?view=graph-rest-1.0
- Microsoft Graph site resource: https://learn.microsoft.com/graph/api/resources/site?view=graph-rest-1.0
- Microsoft Graph authentication methods API overview: https://learn.microsoft.com/graph/api/resources/authenticationmethods-overview?view=graph-rest-1.0
- Microsoft Graph teams/conversation resources: https://learn.microsoft.com/graph/api/resources/teams-api-overview?view=graph-rest-1.0

## Testing and Validation

- At minimum, validate syntax or startup surface for the slice you changed.
- For dependency changes, keep [pyproject.toml](pyproject.toml) and [uv.lock](uv.lock) synchronized.
- For DB changes, validate both fresh initialization and migration behavior.
- For API changes, prefer a focused request-path or startup validation over broad unrelated edits.

## Definition of Done

A change is complete only if all are true:

1. The change respects the existing CLI/app/API/core/DB layering.
2. Any schema change includes migration handling.
3. Proxy, logging, and error-handling behavior remain intentional.
4. Python 3.10+ compatibility is preserved.
5. Relevant Microsoft API assumptions were checked against current Microsoft docs when needed.
6. [pyproject.toml](pyproject.toml) and [uv.lock](uv.lock) remain consistent when dependencies change.
