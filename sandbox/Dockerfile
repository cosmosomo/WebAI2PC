FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUTF8=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:${PATH}" \
    COSMOS_MCP_WORKSPACE=/workspace \
    COSMOS_MCP_STATE_DIR=/state \
    LOCALPC_MCP_STATE_DIR=/state

# Install OS security updates, CA roots (outbound HTTPS/WSS gateways), OpenSSH client (srv.us / VPS tunnels),
# upgrade base setuptools/pip against CVE-2024-6345 / CVE-2025-47273, and pre-create a non-root virtualenv.
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends ca-certificates openssh-client && \
    rm -rf /var/lib/apt/lists/* && \
    python -m pip install --no-cache-dir --upgrade "pip>=24.3.1" "setuptools>=78.1.1" && \
    groupadd -g 1000 cosmos && \
    useradd -m -u 1000 -g 1000 -s /bin/bash cosmos && \
    python -m venv /opt/venv && \
    mkdir -p /app /workspace /state && \
    chown -R 1000:1000 /opt/venv /app /workspace /state

# Drop root privileges BEFORE copying repo sources or executing `pip install` build/install hooks (numeric UID:GID for K8s runAsNonRoot)
USER 1000:1000
WORKDIR /app
COPY --chown=1000:1000 pyproject.toml README.md LICENSE /app/
COPY --chown=1000:1000 src /app/src
COPY --chown=1000:1000 host_skills /app/host_skills

RUN /opt/venv/bin/python -m pip install --no-cache-dir --upgrade "pip>=24.3.1" "setuptools>=78.1.1" && \
    /opt/venv/bin/python -m pip install --no-cache-dir ".[docs]"

VOLUME ["/workspace", "/state"]
EXPOSE 8096

# Entrypoint binds 0.0.0.0:8096 inside the container so host port forwarding (127.0.0.1:8096:8096) works.
# Because Docker bridge requests arrive from 172.x.x.x rather than strict container loopback,
# retrieve the generated owner password & 6-digit dynamic pairing code via:
#   docker exec cosmos-mcp-sandbox cosmos-mcp status --state-dir /state
CMD ["python", "-B", "-m", "cosmos_mcp.launcher.app", "--host", "0.0.0.0", "--port", "8096", "--state-dir", "/state", "--workspace", "/workspace", "--tier", "tier3_workspace_dev"]
