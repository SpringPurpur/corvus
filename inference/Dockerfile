FROM python:3.11-slim

WORKDIR /app

# curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

HEALTHCHECK --interval=5s --timeout=3s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8765/health || exit 1

CMD ["python", "main.py", "--anomaly-only"]
