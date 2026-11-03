# The lab: where the analyst can run its own hunt scripts and test its rules, mid-task.
# Build context is soc-env/ (shared trusted modules are copied in):
#   uv run agent-env env mcp-server put --id lab --dockerfile soc-env/lab/Dockerfile --context soc-env --platform linux/arm64
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir "agentenv-framework-protocol==0.1.350" "mcp>=1.25,<2" "pyyaml>=6,<7"
COPY shared/codescreen.py shared/sigma_lite.py shared/sandboxrun.py shared/bootstrap.py shared/logexport.py ./
COPY lab/server.py .
# The server stays root only so it can demote each run to `runner` (the compose stack has no user/cap knobs).
# `runner` owns nothing; run directories are created per run and removed afterwards. /data is where load_artifact
# copies the incident before data/add.
RUN useradd --uid 10002 --no-create-home --shell /usr/sbin/nologin runner \
    && mkdir -p /lab/datasets /lab/runs /data && chmod 755 /lab/datasets && chmod 711 /lab/runs
CMD ["python", "server.py"]
