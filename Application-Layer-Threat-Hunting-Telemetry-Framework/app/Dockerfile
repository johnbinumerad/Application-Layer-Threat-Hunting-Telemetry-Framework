# Target_API image (build context: repository root).
FROM python:3.12-slim

# iproute2: add the metadata address to lo. setpriv ships with util-linux.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 util-linux \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY labcommon ./labcommon
COPY app ./app
RUN chmod 0755 /srv/app/entrypoint.sh \
    && groupadd --gid 10001 lab && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin lab

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
EXPOSE 8000 8001

# Starts as root only for the `ip addr add`; the entrypoint then drops privileges.
ENTRYPOINT ["/srv/app/entrypoint.sh"]
CMD ["python", "-m", "app.main"]
