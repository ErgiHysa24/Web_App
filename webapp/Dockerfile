# WatchDog Web: immagine unica per l'applicazione web e per il worker.
# Va costruita dalla radice del repository (lo fa docker compose):
#   docker build -f webapp/Dockerfile -t watchdog-web .
# Funziona su Raspberry Pi 4/5 con sistema a 64 bit (linux/arm64) e su PC (linux/amd64).

FROM python:3.12-slim-bookworm AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /src
# Prima le dipendenze (bloccate con hash): questo strato si riusa finché non cambiano.
COPY requirements.txt /src/requirements.txt
COPY webapp/requirements.txt /src/webapp/requirements.txt
RUN pip install --require-hashes -r requirements.txt && \
    pip install --require-hashes -r webapp/requirements.txt
COPY pyproject.toml README.md LICENSE /src/
COPY src /src/src
COPY webapp/pyproject.toml /src/webapp/pyproject.toml
COPY webapp/watchdog_web /src/webapp/watchdog_web
RUN printf 'WatchDog Web\n' > /src/webapp/README.md && \
    pip install --no-deps . ./webapp

FROM python:3.12-slim-bookworm
# nmap serve solo alla scansione "dall'esterno" (dal Raspberry verso il sistema analizzato).
RUN apt-get update -qq && apt-get upgrade -y -qq && apt-get install -y -qq --no-install-recommends nmap && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --uid 10001 --create-home --home-dir /home/watchdog watchdog && \
    mkdir -p /data/reports && chown -R watchdog:watchdog /data
COPY --from=build /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    WATCHDOG_REPORTS_DIR=/data/reports
USER watchdog
WORKDIR /home/watchdog
VOLUME /data/reports
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"
# --proxy-headers: l'indirizzo vero del client arriva dal proxy HTTPS (vedi FORWARDED_ALLOW_IPS nel compose).
CMD ["uvicorn", "--factory", "watchdog_web.app:app_factory", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--no-server-header", "--no-access-log"]
