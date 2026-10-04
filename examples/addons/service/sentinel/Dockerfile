# The inspect_sentinel sidecar as an image. Build from examples/addons/service
# (the sidecar imports ../roxy_layer.py):
#
#   docker build -f sentinel/Dockerfile -t roxy-sentinel examples/addons/service
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY sentinel/requirements.txt sentinel/
RUN pip install --no-cache-dir -r sentinel/requirements.txt
COPY roxy_layer.py ./
COPY sentinel/ sentinel/

USER 65532:65532
ENV HOME=/tmp PYTHONUNBUFFERED=1 SENTINEL_LISTEN=0.0.0.0:9000
EXPOSE 9000
HEALTHCHECK --interval=2s --timeout=2s --retries=30 \
  CMD ["python", "-c", "import socket; socket.create_connection(('127.0.0.1', 9000), 1)"]
CMD ["python", "sentinel/sidecar.py"]
