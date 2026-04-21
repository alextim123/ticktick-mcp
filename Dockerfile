FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCP_TRANSPORT=sse \
    MCP_HOST=0.0.0.0

WORKDIR /app

COPY requirements.txt setup.py ./
COPY ticktick_mcp ./ticktick_mcp

RUN pip install --no-cache-dir .

EXPOSE 10000

CMD ["python", "-m", "ticktick_mcp.cli", "run", "--transport", "sse", "--host", "0.0.0.0"]
