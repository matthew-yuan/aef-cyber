FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir "agentenv-framework-protocol[agent]" "mcp>=1.25,<2" "openai>=1.40"
COPY agent.py .
CMD ["python", "agent.py"]
