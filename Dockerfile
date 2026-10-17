# Bots Bank secure AI gateway: backend API + the staff web page (static files) in ONE image.
# There is no separate frontend build: the page is plain HTML/CSS/JS served by FastAPI.
# Base image python:3.12-slim is published for linux/s390x.

# ---- Stage 1: build the Python packages (ibm_db has no s390x wheel, so it compiles) ----
FROM python:3.12-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY requirements.txt .
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# ---- Stage 2: small runtime image, no compiler, non-root user ----
FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends libxml2 libpam0g \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --no-create-home botsbank
COPY --from=build /opt/venv /opt/venv
WORKDIR /app
COPY botsbank ./botsbank
# Files uploaded from Windows can arrive owner-only; the app runs as a non-root user,
# so make everything world-readable (and read-only for others) inside the image.
RUN chmod -R a+rX,go-w /app
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PORT=8000
USER botsbank
# Secrets (DB_GW_PASSWORD, DEMO_PASSWORD, JWT_SECRET) are NOT in the image: compose injects them.
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request as u; u.urlopen('http://127.0.0.1:%s/health' % os.environ['PORT'], timeout=4)"
CMD ["sh", "-c", "exec uvicorn botsbank.main:app --host 0.0.0.0 --port ${PORT} --proxy-headers"]
