"""Worker: prende le scansioni dalla coda e le esegue, più di una alla volta.

La coda è la tabella `scans`. Per prendere un lavoro si usa `FOR UPDATE SKIP LOCKED`:
più thread (e più container worker) possono chiedere lavoro insieme senza prendersi la
stessa scansione e senza aspettarsi. Regole:

- al massimo WATCHDOG_WORKER_CONCURRENCY scansioni contemporanee per worker;
- una sola scansione alla volta per obiettivo (due insieme installerebbero e
  rimuoverebbero gli stessi pacchetti);
- una scansione "running" il cui worker non dà segni di vita da troppo tempo (riavvio,
  mancanza di corrente sul Raspberry) viene chiusa come non riuscita, non resta appesa.

Avvio: python -m watchdog_web.worker
"""
from __future__ import annotations

import logging
import os
import signal
import socket
import threading
import time
from datetime import timedelta

from sqlalchemy import exists, select, update
from sqlalchemy.orm import Session, aliased, sessionmaker

from watchdog_web.config import Settings, load_settings
from watchdog_web.db import init_schema, make_engine, make_session_factory, session_scope
from watchdog_web.engine import run_scan
from watchdog_web.models import Scan, now
from watchdog_web.security import SecretBox

log = logging.getLogger("watchdog.worker")
POLL_SECONDS = 2.0
STALE_AFTER = timedelta(minutes=10)      # senza heartbeat per così tanto = worker morto


def claim_next(s: Session, worker_name: str) -> int | None:
    """Marca "running" la prossima scansione in coda che si può eseguire e ne restituisce l'id."""
    other = aliased(Scan)
    busy_target = exists().where(other.target_id == Scan.target_id, other.status == "running")
    stmt = (select(Scan).where(Scan.status == "queued", ~busy_target)
            .order_by(Scan.id).limit(1).with_for_update(skip_locked=True))
    scan = s.execute(stmt).scalar_one_or_none()
    if scan is None:
        return None
    if scan.cancel_requested:
        scan.status, scan.finished_at, scan.current_step = "cancelled", now(), "Annullata"
        scan.error = "Annullata prima dell'avvio."
        return None
    scan.status, scan.worker = "running", worker_name[:80]
    scan.started_at = scan.heartbeat_at = now()
    scan.current_step = "In partenza"
    return scan.id


def reap_stale(s: Session, settings: Settings) -> int:
    """Chiude le scansioni rimaste "running" senza un worker vivo. Restituisce quante."""
    limit = now() - STALE_AFTER
    too_long = now() - timedelta(minutes=settings.scan_timeout_minutes)
    stale = s.execute(select(Scan).where(Scan.status == "running").with_for_update(skip_locked=True)).scalars()
    n = 0
    for scan in stale:
        beat = scan.heartbeat_at or scan.started_at
        started = scan.started_at
        if beat is not None and beat.tzinfo is None:        # SQLite nei test
            beat = beat.replace(tzinfo=limit.tzinfo)
        if started is not None and started.tzinfo is None:
            started = started.replace(tzinfo=limit.tzinfo)
        if (beat is None or beat < limit) or (started is not None and started < too_long):
            scan.status, scan.finished_at, scan.current_step = "failed", now(), "Non riuscita"
            scan.error = ("La scansione si è interrotta: il worker che la eseguiva non risponde più "
                          "(riavvio o spegnimento). Sul sistema analizzato possono essere rimasti dei tool "
                          "installati: rilancia la scansione, che li riconosce e a fine lavoro pulisce.")
            n += 1
    return n


class Worker:
    def __init__(self, factory: sessionmaker[Session], settings: Settings, box: SecretBox,
                 name: str | None = None) -> None:
        self.factory, self.settings, self.box = factory, settings, box
        self.name = name or f"{socket.gethostname()}-{os.getpid()}"
        self.stop = threading.Event()
        self._slots = threading.Semaphore(settings.worker_concurrency)
        self._threads: list[threading.Thread] = []

    def run_once(self) -> bool:
        """Prova a prendere e avviare una scansione. True se ne ha avviata una."""
        if not self._slots.acquire(blocking=False):
            return False
        try:
            with session_scope(self.factory) as s:
                scan_id = claim_next(s, self.name)
        except Exception:
            self._slots.release()
            raise
        if scan_id is None:
            self._slots.release()
            return False
        t = threading.Thread(target=self._run, args=(scan_id,), name=f"scan-{scan_id}", daemon=True)
        self._threads.append(t)
        t.start()
        return True

    def _heartbeat(self, scan_id: int, done: threading.Event) -> None:
        """Segnale di vita ogni 30 secondi: un tool può lavorare molti minuti senza passi nuovi."""
        while not done.wait(30):
            try:
                with session_scope(self.factory) as s:
                    s.execute(update(Scan).where(Scan.id == scan_id, Scan.status == "running")
                              .values(heartbeat_at=now()))
            except Exception:
                log.exception("scansione %s: heartbeat non riuscito", scan_id)

    def _run(self, scan_id: int) -> None:
        done = threading.Event()
        threading.Thread(target=self._heartbeat, args=(scan_id, done), daemon=True).start()
        try:
            log.info("scansione %s: avvio", scan_id)
            run_scan(scan_id, self.factory, self.settings, self.box)
            log.info("scansione %s: finita", scan_id)
        except BaseException:      # run_scan non solleva; questo protegge il thread comunque
            log.exception("scansione %s: errore inatteso", scan_id)
        finally:
            done.set()
            self._slots.release()

    def loop(self) -> None:
        log.info("worker %s avviato: %s scansioni contemporanee", self.name, self.settings.worker_concurrency)
        last_reap = 0.0
        while not self.stop.is_set():
            try:
                if time.monotonic() - last_reap > 60:
                    with session_scope(self.factory) as s:
                        n = reap_stale(s, self.settings)
                    if n:
                        log.warning("chiuse %s scansioni rimaste appese", n)
                    last_reap = time.monotonic()
                started = self.run_once()
            except Exception:
                log.exception("errore nel ciclo del worker (riprovo)")
                started = False
            if not started:
                self.stop.wait(POLL_SECONDS)
        self.shutdown()

    def shutdown(self, wait_seconds: float = 25) -> None:
        """Arresto ordinato: chiede l'annullamento delle scansioni in corso, così fanno la pulizia."""
        running = [t for t in self._threads if t.is_alive()]
        if not running:
            return
        log.info("arresto: annullo %s scansioni in corso e attendo la pulizia", len(running))
        with session_scope(self.factory) as s:
            s.execute(update(Scan).where(Scan.status == "running", Scan.worker == self.name)
                      .values(cancel_requested=True))
        deadline = time.monotonic() + wait_seconds
        for t in running:
            t.join(max(0.0, deadline - time.monotonic()))


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = load_settings()
    engine = make_engine(settings.database_url)
    init_schema(engine)
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    worker = Worker(make_session_factory(engine), settings, SecretBox(settings.secret_key))
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: worker.stop.set())
    worker.loop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
