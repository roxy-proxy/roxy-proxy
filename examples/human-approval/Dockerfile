# The human-approval layer: approval.py and the quickstart sentinel modules
# it imports, laid out as in the repository so the relative imports hold.
# The build context is examples/ (see compose.yaml).
# python:3.12-slim, pinned by digest (multi-arch index); bump deliberately.
FROM python:3.12-slim@sha256:ddb0207ae1f0356c2b724d740769b0c5f5f51cc54a0525178f721825f78fe74c

# pip installs inspect_sentinel (and its inspect_ai branch) from git.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app/human-approval
COPY quickstart/sentinel/requirements.txt ../quickstart/sentinel/
COPY human-approval/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY quickstart/sentinel/*.py ../quickstart/sentinel/
COPY human-approval/*.py human-approval/review.html ./
# The Inspect log; a volume mounted here inherits the ownership.
RUN mkdir /logs && chown 65532:65532 /logs

USER 65532:65532
ENV HOME=/tmp PYTHONUNBUFFERED=1
EXPOSE 9000 8585
# Each probe is a connection the layer logs, so probe quickly only until it is up.
HEALTHCHECK --interval=30s --start-period=60s --start-interval=2s --timeout=2s --retries=3 \
  CMD ["python", "-c", "import socket; socket.create_connection(('127.0.0.1', 9000), 1)"]
CMD ["python", "approval.py", "--listen", "0.0.0.0:9000", "--ui", "0.0.0.0:8585", "--log-dir", "/logs"]
