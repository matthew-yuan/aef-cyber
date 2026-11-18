# The scorebox: the offline container where the analyst's code is executed and graded.
# Started by run_docker_container with network "none"; the grader runs as `runner` with the LLM variables blanked.
FROM python:3.12-slim
RUN pip install --no-cache-dir "pyyaml>=6,<7" \
    && useradd --uid 10003 --no-create-home --shell /usr/sbin/nologin runner \
    && mkdir -p /harness /handoff /work/out /work/runs /work/artifacts && chown -R runner /handoff /work
COPY harness/ /harness/
COPY data/ /harness/data/
RUN chmod -R a+rX /harness
USER runner
WORKDIR /work
CMD ["sleep", "infinity"]
