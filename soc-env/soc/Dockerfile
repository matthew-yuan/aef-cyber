FROM python:3.12-slim
WORKDIR /app
# Pinned to the protocol version agentenv-framework 0.9.1335 was released with, as in its echo-mcp example.
RUN pip install --no-cache-dir "agentenv-framework-protocol==0.1.350" "mcp>=1.25,<2"
COPY server.py .
# load_artifact copies the incident file to /data/<filename> with a `docker exec mkdir -p /data` run as this
# image's user, so /data has to exist and belong to it.
RUN useradd --create-home --uid 10001 appuser && mkdir /data && chown appuser /data
USER appuser
CMD ["python", "server.py"]
