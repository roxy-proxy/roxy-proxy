# The quickstart's inspect_sentinel sidecar, and Inspect View over its log.
FROM python:3.12-slim

# pip installs inspect_sentinel (and its inspect_ai branch) from git.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py ./
# The Inspect log; a volume mounted here inherits the ownership.
RUN mkdir /logs && chown 65532:65532 /logs

USER 65532:65532
ENV HOME=/tmp PYTHONUNBUFFERED=1 SENTINEL_LISTEN=0.0.0.0:9000
EXPOSE 9000
HEALTHCHECK --interval=2s --timeout=2s --retries=30 \
  CMD ["python", "-c", "import socket; socket.create_connection(('127.0.0.1', 9000), 1)"]
CMD ["python", "sidecar.py"]
