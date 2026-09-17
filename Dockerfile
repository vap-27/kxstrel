# Browserless by construction: stock python-slim image, pip packages only.
# Nothing here installs or downloads Chromium/Chrome/Puppeteer/Playwright/
# Selenium (enforced by scripts/audit_browserless.py in CI and pre-deploy).
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/kxstrel-x-mcp

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY app ./app
COPY scripts ./scripts

# scripts/ ships inside the image so the image can audit itself before deploy:
#   docker run --rm --entrypoint python <image> scripts/audit_browserless.py --strict-binaries
# Strict mode gates on a clean PATH. Inside this image that assertion is
# meaningful; on a dev box or a CI runner with preinstalled browsers it is not,
# which is why CI runs the default (project-scoped) mode.

RUN useradd --create-home appuser \
    && mkdir -p /srv/kxstrel-x-mcp/data /tmp/kxstrel \
    && chown -R appuser:appuser /srv/kxstrel-x-mcp /tmp/kxstrel
USER appuser

EXPOSE 8000

# python -m app.main (not bare uvicorn) so uvicorn runs with log_config=None
# and our redacting log handler owns every logger; access logs stay off.
# Local plaintext pool cache goes to ephemeral /tmp, 0600.
ENV SPECTRE_DB_PATH=/tmp/kxstrel/kxstrel-accs.db
ENV KXSTREL_DB_PATH=/tmp/kxstrel/kxstrel-accs.db

# Single worker: MCP Streamable HTTP sessions are in-memory.
# Render injects $PORT; default 8000 for local runs.
CMD ["sh", "-c", "python -m app.main"]
