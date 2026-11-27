FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUTF8=1 \
    PIP_NO_CACHE_DIR=1 \
    COSMOS_MCP_WORKSPACE=/workspace \
    COSMOS_MCP_STATE_DIR=/state \
    LOCALPC_MCP_STATE_DIR=/state

# Install CA roots (outbound HTTPS/WSS gateways) and OpenSSH client (srv.us / VPS tunnels)
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates openssh-client && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -g 1000 cosmos && \
    useradd -m -u 1000 -g 1000 -s /bin/bash cosmos && \
    mkdir -p /app /workspace /state && \
    chown -R cosmos:cosmos /app /workspace /state

WORKDIR /app
COPY --chown=cosmos:cosmos pyproject.toml README.md LICENSE /app/
COPY --chown=cosmos:cosmos src /app/src
COPY --chown=cosmos:cosmos host_skills /app/host_skills

RUN pip install --disable-pip-version-check ".[docs]"

USER cosmos
VOLUME ["/workspace", "/state"]
EXPOSE 8096

# Entrypoint binds 0.0.0.0:8096 inside the container so host port forwarding (127.0.0.1:8096:8096) works.
# Because Docker bridge requests arrive from 172.x.x.x rather than strict container loopback,
# retrieve the generated owner password & 6-digit dynamic pairing code via:
#   docker exec cosmos-mcp-sandbox cosmos-mcp status --state-dir /state
CMD ["python", "-B", "-m", "cosmos_mcp.launcher.app", "--host", "0.0.0.0", "--port", "8096", "--state-dir", "/state", "--workspace", "/workspace", "--tier", "tier3_workspace_dev"]
