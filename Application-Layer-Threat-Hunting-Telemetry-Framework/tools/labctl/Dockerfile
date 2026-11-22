# lab-setup image (build context: repository root).
FROM python:3.12-slim

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY labcommon ./labcommon
COPY tools ./tools
COPY config ./config
COPY infra/opensearch ./infra/opensearch
COPY opensearch ./opensearch

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN groupadd --gid 10001 lab && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin lab
USER lab

ENTRYPOINT ["python", "-m", "tools.labctl", "setup"]
