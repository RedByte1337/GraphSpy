# Development Guide

This guide covers the technical architecture, request lifecycle, schema model, and extension rules for GraphSpy.

## Design Principles

GraphSpy should continue to follow these rules:

### Single Responsibility Principle (SRP)

Further reading: [Wikipedia - Single-responsibility principle](https://en.wikipedia.org/wiki/Single-responsibility_principle), [Refactoring.Guru - Single Responsibility Principle](https://refactoring.guru/design-patterns/solid-principles#single-responsibility-principle)

Keep each layer focused on one concern:
* [src/graphspy/cli.py](src/graphspy/cli.py) owns startup, argument parsing, and process wiring.
* [src/graphspy/app.py](src/graphspy/app.py) owns Flask app composition and cross-cutting handlers.
* Files in [src/graphspy/api](src/graphspy/api) own HTTP input/output handling.
* Files in [src/graphspy/core](src/graphspy/core) own Microsoft protocol workflows, token logic, and business behavior.
* Files in [src/graphspy/db](src/graphspy/db) own SQLite access, schema creation, and migration logic.
* [src/graphspy/web/pages.py](src/graphspy/web/pages.py) should remain route-to-template wiring, not a second business-logic layer.

### Open/Closed Principle (OCP)

Further reading: [Wikipedia - Open-closed principle](https://en.wikipedia.org/wiki/Open%E2%80%93closed_principle), [Refactoring.Guru - Open Closed Principle](https://refactoring.guru/design-patterns/solid-principles#open-closed-principle)

Extend behavior by adding focused modules or helper functions instead of rewriting shared plumbing:
* New UI/API capability usually means a focused API module or endpoint plus a matching page/template when needed.
* New outbound workflow logic belongs in the relevant file under [src/graphspy/core](src/graphspy/core).
* Shared HTTP behavior should be extended through [src/graphspy/core/requests_.py](src/graphspy/core/requests_.py), not reimplemented ad hoc.
* Schema changes must remain compatible with both fresh initialization and upgrade paths.

### Composition over sprawl

Further reading: [Wikipedia - Composition over inheritance](https://en.wikipedia.org/wiki/Composition_over_inheritance), [Refactoring.Guru - Favor Composition Over Inheritance](https://refactoring.guru/favor-composition-over-inheritance)

GraphSpy is mostly module-based composition rather than inheritance-heavy OOP:
* [src/graphspy/app.py](src/graphspy/app.py) composes the application by registering API and page blueprints.
* API modules should compose helpers from [src/graphspy/core](src/graphspy/core) and [src/graphspy/db](src/graphspy/db) instead of embedding their own versions.
* Keep helpers small and reusable so new features can be assembled from existing building blocks.

### Thin API, thick core

API modules should translate HTTP requests into calls to core logic, then format the response.
They should not own protocol semantics, token derivation, throttling strategy, or database design.

Representative examples:
* [src/graphspy/api/access_tokens.py](src/graphspy/api/access_tokens.py) is thin and delegates token persistence/decoding behavior.
* [src/graphspy/core/requests_.py](src/graphspy/core/requests_.py) centralizes outbound request behavior, proxy handling, retry logic, and response shaping.

### DRY and consistent conventions

Further reading: [Wikipedia - Don't repeat yourself](https://en.wikipedia.org/wiki/Don%27t_repeat_yourself), [DevIQ - DRY Principle](https://deviq.com/principles/dont-repeat-yourself)

Reuse the existing conventions and shared helpers:
* Use [src/graphspy/logbook.py](src/graphspy/logbook.py) for logging setup and behavior.
* Use [src/graphspy/core/errors.py](src/graphspy/core/errors.py) for application-level errors that should flow through Flask handlers.
* Use [src/graphspy/db/connection.py](src/graphspy/db/connection.py) for request-scoped SQLite access.
* Use [src/graphspy/api/helpers.py](src/graphspy/api/helpers.py) where a shared API response helper makes sense.

### Fail fast and observable behavior

GraphSpy is an operator tool. Hidden behavior changes are risky.
* Prefer explicit errors over silent fallback.
* Preserve operator-visible behavior unless the change explicitly targets it.
* Keep logging consistent so requests, failures, and migrations remain debuggable.
* Do not silently remove proxy support, retries, or intentional certificate-verification bypass under proxied operation.

## Architecture

GraphSpy has four primary layers.

### 1. CLI and process startup

[src/graphspy/cli.py](src/graphspy/cli.py) is the entry point.
It is responsible for:
* parsing interface, port, database, proxy, debug, and dev flags
* resolving the application directory and database path
* bootstrapping the database on first use
* creating the Flask app
* launching Waitress in normal mode or the Flask development server in dev mode

This file should stay focused on process-level orchestration, not product feature logic.

### 2. Flask application composition

[src/graphspy/app.py](src/graphspy/app.py) creates the Flask app and configures shared behavior.

Current responsibilities:
* configure app paths and runtime settings
* register all API blueprints and the page blueprint
* log requests in `after_request`
* translate `AppError` into JSON responses
* close the SQLite connection on app-context teardown
* suppress duplicate Werkzeug request logging

This file is the right place for app-wide middleware-style behavior, not feature-specific Microsoft logic.

### 3. API and web layer

API modules under [src/graphspy/api](src/graphspy/api) expose HTTP endpoints.
Typical responsibilities:
* read form/query/path input
* perform light validation
* delegate to core or DB helpers
* return JSON, redirects, or simple values

The page blueprint in [src/graphspy/web/pages.py](src/graphspy/web/pages.py) maps routes to templates and should remain intentionally thin.

Templates and assets live under:
* [src/graphspy/web/templates](src/graphspy/web/templates)
* [src/graphspy/web/static](src/graphspy/web/static)

### 4. Core workflows and data layer

Core modules under [src/graphspy/core](src/graphspy/core) implement the real M365 / Entra workflows.
Representative modules:
* [src/graphspy/core/tokens.py](src/graphspy/core/tokens.py)
* [src/graphspy/core/device_codes.py](src/graphspy/core/device_codes.py)
* [src/graphspy/core/device.py](src/graphspy/core/device.py)
* [src/graphspy/core/prt.py](src/graphspy/core/prt.py)
* [src/graphspy/core/winhello.py](src/graphspy/core/winhello.py)
* [src/graphspy/core/mfa.py](src/graphspy/core/mfa.py)
* [src/graphspy/core/teams.py](src/graphspy/core/teams.py)
* [src/graphspy/core/requests_.py](src/graphspy/core/requests_.py)

The data layer under [src/graphspy/db](src/graphspy/db) owns:
* connection lifecycle through Flask `g`
* schema bootstrap
* schema migrations
* raw query/execute helpers

## Request Lifecycle

A normal request path looks like this:

1. [src/graphspy/cli.py](src/graphspy/cli.py) starts the process and creates the app.
2. [src/graphspy/app.py](src/graphspy/app.py) registers blueprints and global handlers.
3. A route in [src/graphspy/api](src/graphspy/api) or [src/graphspy/web/pages.py](src/graphspy/web/pages.py) receives the request.
4. API modules delegate to [src/graphspy/core](src/graphspy/core) and/or [src/graphspy/db](src/graphspy/db).
5. Shared DB access flows through [src/graphspy/db/connection.py](src/graphspy/db/connection.py).
6. Outbound Microsoft requests should generally flow through [src/graphspy/core/requests_.py](src/graphspy/core/requests_.py).
7. [src/graphspy/app.py](src/graphspy/app.py) logs the response and tears down DB state.

If an application-level failure should be surfaced cleanly, raise [src/graphspy/core/errors.py](src/graphspy/core/errors.py) `AppError` so the global error handler can respond consistently.

## Database Model

### Schema bootstrap

[src/graphspy/db/schema.py](src/graphspy/db/schema.py) defines the current schema for a fresh database.
It currently creates tables for:
* access tokens
* refresh tokens
* device codes
* request templates
* Teams settings
* MFA OTP secrets
* device certificates
* primary refresh tokens
* Windows Hello keys
* settings

Fresh bootstrap writes the current schema version to `settings`.

### Migrations

[src/graphspy/db/migrations.py](src/graphspy/db/migrations.py) upgrades older databases in-place by stepping through schema versions sequentially.

Rules:
* Never update only the fresh schema and forget upgrades.
* Never update only migrations and forget fresh installs.
* Prefer additive migrations that preserve existing operator data.
* Keep schema version changes explicit and linear.

If you add a table or column, update both files in the same change.

## Feature Boundaries

Start in these files for common work:

* Access and refresh tokens:
  - [src/graphspy/api/access_tokens.py](src/graphspy/api/access_tokens.py)
  - [src/graphspy/api/refresh_tokens.py](src/graphspy/api/refresh_tokens.py)
  - [src/graphspy/core/tokens.py](src/graphspy/core/tokens.py)
* Device codes:
  - [src/graphspy/api/device_codes.py](src/graphspy/api/device_codes.py)
  - [src/graphspy/core/device_codes.py](src/graphspy/core/device_codes.py)
* Device registration and certificates:
  - [src/graphspy/api/devices.py](src/graphspy/api/devices.py)
  - [src/graphspy/core/device.py](src/graphspy/core/device.py)
* PRT and Windows Hello:
  - [src/graphspy/core/prt.py](src/graphspy/core/prt.py)
  - [src/graphspy/core/winhello.py](src/graphspy/core/winhello.py)
* MFA:
  - [src/graphspy/api/mfa.py](src/graphspy/api/mfa.py)
  - [src/graphspy/core/mfa.py](src/graphspy/core/mfa.py)
* Generic Graph/custom requests:
  - [src/graphspy/api/requests_.py](src/graphspy/api/requests_.py)
  - [src/graphspy/core/requests_.py](src/graphspy/core/requests_.py)
* Entra data retrieval:
  - [src/graphspy/api/entra.py](src/graphspy/api/entra.py)
* Teams:
  - [src/graphspy/api/teams.py](src/graphspy/api/teams.py)
  - [src/graphspy/core/teams.py](src/graphspy/core/teams.py)

## Request, Proxy, and HTTP Rules

Outbound Microsoft requests should stay behaviorally consistent.

* Prefer [src/graphspy/core/requests_.py](src/graphspy/core/requests_.py) for outbound HTTP so headers, user-agent behavior, proxy settings, and retry logic stay centralized.
* If a proxy is configured, the current code intentionally sets `verify=False` unless explicitly overridden. That is part of the operator workflow for this tool and should not be casually changed.
* Preserve the existing retry behavior for HTTP 429 with `Retry-After` unless the task is specifically about throttling behavior.
* Preserve user-agent conventions already used by the tool.

## Logging and Error Handling

* Logging is configured in [src/graphspy/logbook.py](src/graphspy/logbook.py) with Loguru and stdlib interception.
* Request logging is done centrally in [src/graphspy/app.py](src/graphspy/app.py).
* Use explicit, operator-meaningful error messages.
* Use `logger.exception(...)` when stack traces matter during exception handling.
* Use `AppError` for controlled application-level failures that should return a clean JSON error.

## Python Conventions

* Python baseline is 3.10+.
* Use modern typing syntax compatible with 3.10+.
* Group imports with explicit section comments.
* Prefer small focused helpers over large mixed-purpose functions.
* Avoid broad refactors in unrelated files.
* Keep diffs minimal and behavior-preserving unless a behavioral change is the point of the task.

## Microsoft Documentation

When service semantics matter, check Microsoft docs before changing behavior.

* Microsoft Graph overview: https://learn.microsoft.com/graph/overview
* Microsoft Graph REST API overview: https://learn.microsoft.com/graph/api/overview?view=graph-rest-1.0
* Microsoft Graph throttling guidance: https://learn.microsoft.com/graph/throttling
* Microsoft identity platform OAuth 2.0 device authorization grant: https://learn.microsoft.com/entra/identity-platform/v2-oauth2-device-code
* Microsoft Graph auth concepts: https://learn.microsoft.com/graph/auth/auth-concepts
* Microsoft Graph user resource: https://learn.microsoft.com/graph/api/resources/user?view=graph-rest-1.0
* Microsoft Graph driveItem resource: https://learn.microsoft.com/graph/api/resources/driveitem?view=graph-rest-1.0
* Microsoft Graph site resource: https://learn.microsoft.com/graph/api/resources/site?view=graph-rest-1.0
* Microsoft Graph authentication methods overview: https://learn.microsoft.com/graph/api/resources/authenticationmethods-overview?view=graph-rest-1.0
* Microsoft Teams API overview: https://learn.microsoft.com/graph/api/resources/teams-api-overview?view=graph-rest-1.0

## AI Usage

When using AI in any shape or form during development, please make sure to adhere to the [AI policy](AI_POLICY.md)!

## Definition of Done

A change is not complete until all are true:

1. The change respects the CLI/app/API/core/DB boundaries described here.
2. Schema changes update both fresh bootstrap and migration handling.
3. Proxy, retry, and logging behavior remain intentional.
4. Python 3.10+ compatibility is preserved.
5. Relevant Microsoft API semantics were checked when behavior depends on them.
6. [pyproject.toml](pyproject.toml) and [uv.lock](uv.lock) stay in sync when dependencies change.
