FROM python:3.14-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
WORKDIR /app
COPY pyproject.toml uv.lock /app
RUN uv sync --no-install-project --frozen
COPY . /app
RUN uv sync --no-editable --frozen

FROM python:3.14-slim
WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"
ENTRYPOINT ["python", "-m", "graphspy", "-i", "0.0.0.0", "-p", "8080"]
