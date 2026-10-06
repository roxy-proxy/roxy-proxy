# The quickstart's mock services (fake model, auth service, quota board) and
# the chat client, in one image; compose picks the script per service.
# python:3.12-slim, pinned by digest (multi-arch index); bump deliberately.
FROM python:3.12-slim@sha256:ddb0207ae1f0356c2b724d740769b0c5f5f51cc54a0525178f721825f78fe74c

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py *.json *.html ./

USER 65532:65532
ENV HOME=/tmp PYTHONUNBUFFERED=1
