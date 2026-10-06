# The quickstart's control plane: the server side of the roxy node protocol.
# python:3.12-slim, pinned by digest (multi-arch index); bump deliberately.
FROM python:3.12-slim@sha256:ddb0207ae1f0356c2b724d740769b0c5f5f51cc54a0525178f721825f78fe74c

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY controlplane.py ./

USER 65532:65532
ENV HOME=/tmp PYTHONUNBUFFERED=1 PORT=8443
EXPOSE 8443
HEALTHCHECK --interval=2s --timeout=2s --retries=30 \
  CMD ["python", "-c", "import socket; socket.create_connection(('127.0.0.1', 8443), 1)"]
CMD ["python", "controlplane.py"]
