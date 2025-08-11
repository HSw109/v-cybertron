# Dockerfile
FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
# Pin versions (change as you like)
ARG SEMGREP_VERSION=1.131.0
ARG BANDIT_VERSION=1.8.6
ARG GITLEAKS_VERSION=8.28.0
ARG GO_VERSION=1.24.5
# Base OS deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git jq python3 python3-pip \
 && rm -rf /var/lib/apt/lists/*

# Semgrep + Bandit via pip (system-wide)
RUN python3 -m pip install --no-cache-dir \
      "semgrep==${SEMGREP_VERSION}" \
      "bandit==${BANDIT_VERSION}"

COPY ./requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --no-cache-dir -r /tmp/requirements.txt
# Gitleaks via official release binary
# (release path uses 'vX.Y.Z' and asset name includes the same string)
RUN curl -fsSL \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
      -o /tmp/gitleaks.tgz \
 && tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks \
 && rm -f /tmp/gitleaks.tgz \
 && /usr/local/bin/gitleaks version

COPY ./app /app
# Non-root user + working directory
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser
WORKDIR /app


# Default to an interactive shell; override with the tool you want
CMD ["python3", "server.py"]
