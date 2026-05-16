FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml .
COPY pega_pega/ pega_pega/

RUN pip install --no-cache-dir . && \
    apt-get purge -y gcc && apt-get autoremove -y

RUN mkdir -p /data /app/.certs

ENV PEGA_DB_PATH=/data/pega_pega.db

EXPOSE 21 22 23 25 53/udp 53/tcp 80 110 143 161/udp 389 443 514/udp 3306 8443 9999

ENTRYPOINT ["pega-pega"]
CMD ["--db", "/data/pega_pega.db"]
