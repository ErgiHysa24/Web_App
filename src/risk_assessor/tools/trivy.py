"""Trivy (Aqua Security): vulnerabilità note nei pacchetti del sistema.

Esegue `trivy rootfs /` solo con lo scanner delle vulnerabilità e solo per quelle
che hanno già una correzione (`--ignore-unfixed`). Non cerca segreti né errori di
configurazione: il report non deve contenere password o chiavi del sistema analizzato.

Installazione (solo se Trivy manca e l'installazione è consentita)
-----------------------------------------------------------------
Trivy non è nei repository standard. Lo strumento scarica il binario della versione
FISSATA qui sotto dalla release ufficiale su GitHub e lo usa solo se lo SHA-256 del
file scaricato coincide con quello scritto in questo file (i valori vengono dal file
`trivy_<versione>_checksums.txt` della release). Se non coincide, il file viene scartato
e nulla viene eseguito. Il binario sta in una cartella temporanea privata (con anche la
cache del database), non tocca il sistema e non richiede sudo; a fine scansione la
cartella viene cancellata. Per aggiornare Trivy bisogna cambiare versione E checksum.

Servono accesso a internet sul target (download del binario e, al primo avvio, del
database delle vulnerabilità) e `curl` o `wget`.
"""
from __future__ import annotations

import re

from risk_assessor.executor import BaseExecutor
from risk_assessor.host import HostInfo, has_command
from risk_assessor.lifecycle.installation import InstallState
from risk_assessor.models import Finding
from risk_assessor.parsers.trivy import parse_trivy
from risk_assessor.tools.base import SecurityTool

TRIVY_VERSION = "0.76.0"
_BASE_URL = f"https://github.com/aquasecurity/trivy/releases/download/v{TRIVY_VERSION}"
# SHA-256 da trivy_0.76.0_checksums.txt (release ufficiale v0.76.0)
TRIVY_SHA256 = {
    "Linux-64bit": "e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7",
    "Linux-ARM64": "aab21e677a7b7071fc79f1711480840754c18a1b9d9cefa7ccd06af63a0e8f4c",
}
_ARCH = {"x86_64": "Linux-64bit", "amd64": "Linux-64bit",
         "aarch64": "Linux-ARM64", "arm64": "Linux-ARM64"}

# download del database + lettura dei pacchetti: qualche minuto al primo avvio.
TRIVY_TIMEOUT = 1200
DOWNLOAD_TIMEOUT = 600

_SKIP_DIRS = ("/proc", "/sys", "/dev", "/run", "/mnt", "/media")
# la cartella temporanea viene da `mktemp` sul target: la si usa (e la si cancella)
# solo se ha esattamente questa forma.
_WORKDIR_RE = re.compile(r"/tmp/watchdog-trivy\.[A-Za-z0-9]{6,12}")


# Famiglie i cui pacchetti Trivy sa riconoscere. Su Fedora e Arch non ne trova nessuno
# e direbbe "0 vulnerabilità": sarebbe un falso "tutto a posto", quindi non si esegue.
_TRIVY_FAMILIES = frozenset({"debian", "rhel", "suse", "alpine"})


class TrivyTool(SecurityTool):
    name = "trivy"
    package = None

    def unsupported_reason(self, host: HostInfo) -> str | None:
        reason = super().unsupported_reason(host)
        if reason:
            return reason
        if host.is_linux and host.family not in _TRIVY_FAMILIES:
            return f"Trivy non riconosce i pacchetti di {host.pretty or host.family_label}"
        return None

    def __init__(self) -> None:
        super().__init__()
        self._workdir: str | None = None

    # ------------------------------------------------------------ installazione
    def install_custom(self, executor: BaseExecutor, tracker, sudo_ctx=None):
        arch_out, _, rc = executor.execute_command(["uname", "-m"])
        asset = _ARCH.get(arch_out.strip()) if rc == 0 else None
        if asset is None:
            tracker.record(self.name, "trivy", InstallState.FAILED_INSTALL)
            return InstallState.FAILED_INSTALL

        out, _, rc = executor.execute_command(["mktemp", "-d", "/tmp/watchdog-trivy.XXXXXXXX"])
        workdir = out.strip()
        if rc != 0 or not _WORKDIR_RE.fullmatch(workdir):
            tracker.record(self.name, "trivy", InstallState.FAILED_INSTALL)
            return InstallState.FAILED_INSTALL

        def remover(ex: BaseExecutor, _sudo=None) -> bool:
            _, _, r = ex.execute_command(["rm", "-rf", "--", workdir])
            return r == 0

        if self._download_and_verify(executor, workdir, asset):
            self._workdir = workdir
            self._path = f"{workdir}/trivy"
            tracker.record(self.name, "trivy", InstallState.INSTALLED_BY_ASSESSOR, remover)
            return InstallState.INSTALLED_BY_ASSESSOR

        remover(executor)
        tracker.record(self.name, "trivy", InstallState.FAILED_INSTALL)
        return InstallState.FAILED_INSTALL

    def _download_and_verify(self, executor: BaseExecutor, workdir: str, asset: str) -> bool:
        archive = f"{workdir}/trivy.tar.gz"
        url = f"{_BASE_URL}/trivy_{TRIVY_VERSION}_{asset}.tar.gz"
        if has_command(executor, "curl"):
            cmd = ["curl", "-fsSL", "--proto", "=https", "--tlsv1.2", "-o", archive, url]
        elif has_command(executor, "wget"):
            cmd = ["wget", "-q", "-O", archive, url]
        else:
            return False
        if executor.execute_command(cmd, timeout=DOWNLOAD_TIMEOUT)[2] != 0:
            return False

        out, _, rc = executor.execute_command(["sha256sum", archive])
        digest = out.split()[0].lower() if rc == 0 and out.split() else ""
        if digest != TRIVY_SHA256[asset]:
            return False  # file diverso da quello pubblicato: non si esegue niente

        if executor.execute_command(["tar", "-xzf", archive, "-C", workdir, "trivy"])[2] != 0:
            return False
        if executor.execute_command(["chmod", "700", f"{workdir}/trivy"])[2] != 0:
            return False
        return executor.execute_command(["test", "-x", f"{workdir}/trivy"])[2] == 0

    # ------------------------------------------------------------------ uso
    def run(self, executor: BaseExecutor, target: str | None = None) -> str:
        cmd = [
            self._path, "rootfs", "/",
            # Solo i pacchetti del sistema: le librerie dei linguaggi sparse sul disco
            # (toolchain, node_modules, virtualenv) rallenterebbero di molto la scansione
            # e riguardano le applicazioni, non l'host.
            "--format", "json", "--scanners", "vuln", "--pkg-types", "os", "--ignore-unfixed",
            "--quiet", "--timeout", "15m", "--no-progress",
        ]
        skip = list(_SKIP_DIRS)
        if self._workdir:
            # database e cache restano nella cartella temporanea e spariscono con lei
            cmd += ["--cache-dir", f"{self._workdir}/cache"]
            # e la cartella non va analizzata: altrimenti Trivy segnala le librerie del
            # proprio binario come vulnerabilità del sistema.
            skip.append(self._workdir)
        for d in skip:
            cmd += ["--skip-dirs", d]
        out, err, rc = executor.execute_command(cmd, timeout=TRIVY_TIMEOUT)
        if out and out.strip():
            return out
        return err or ""

    def parse(self, raw_output: str) -> list[Finding]:
        return parse_trivy(raw_output)

    def version(self, executor: BaseExecutor) -> str | None:
        out, _, rc = executor.execute_command([self._path, "--version"])
        return out.strip().splitlines()[0] if rc == 0 and out.strip() else None
