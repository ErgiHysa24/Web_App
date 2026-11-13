"""OpenSCAP integration.

OpenSCAP richiede un datastream SCAP (SSG) per valutare profili CIS/STIG.
Il datastream deve essere quello della distribuzione e della versione del
target: un contenuto pensato per un altro sistema (per esempio Debian 12 su
Ubuntu 24.04) rende tutte le regole "non applicabili" e darebbe un falso
"tutto ok". Se il datastream giusto non c'è, il parser lo segnala.
"""
from __future__ import annotations

import re

from risk_assessor.executor import BaseExecutor
from risk_assessor.host import HostInfo, privileged_prefix
from risk_assessor.lifecycle.installation import InstallState, ensure_tool_installed
from risk_assessor.models import Finding
from risk_assessor.parsers.openscap import parse_openscap
from risk_assessor.tools.base import SecurityTool, ToolState, find_tool


SSG_DIR = "/usr/share/xml/scap/ssg/content"

# Usato solo se /etc/os-release non è leggibile.
SSG_PATHS = [
    "/usr/share/xml/scap/ssg/content/ssg-debian13-ds.xml",
    "/usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml",
    "/usr/share/xml/scap/ssg/content/ssg-debian11-ds.xml",
    "/usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml",
    "/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml",
    "/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml",
    "/usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml",
]

DEFAULT_PROFILE = "xccdf_org.ssgproject.content_profile_standard"

# Se il datastream non ha il profilo di default, si usa il primo disponibile di questi.
PROFILE_FALLBACKS = [
    "xccdf_org.ssgproject.content_profile_standard",
    "xccdf_org.ssgproject.content_profile_cis_level1_server",
    "xccdf_org.ssgproject.content_profile_cis_server_l1",
    "xccdf_org.ssgproject.content_profile_cis",
    "xccdf_org.ssgproject.content_profile_anssi_bp28_minimal",
]

# Prefisso con cui i pacchetti SSG sono registrati nel tracker (per il cleanup).
SSG_TRACKER_KEY = "oscap-content"

SSG_PACKAGE_CANDIDATES = [
    "ssg-debian",
    "scap-security-guide",
    "ssg-base",
]

# Pacchetti con il contenuto SSG per famiglia di distribuzione.
SSG_PACKAGES_BY_OS = {
    "debian": ["ssg-debian"],
    "ubuntu": ["ssg-debderived"],
    "rhel": ["scap-security-guide"],
    "fedora": ["scap-security-guide"],
    "suse": ["scap-security-guide"],
}

# Versioni i cui repository non hanno (ancora) il contenuto SCAP per sé stesse
# (verificato installando i pacchetti nelle immagini ufficiali, novembre 2026):
# Ubuntu 22.04 non ha OpenSCAP; ssg-debderived di Ubuntu 24.04 arriva a ubuntu2204;
# ssg-debian di Debian 13 arriva a debian12.
SSG_MISSING = {("ubuntu", "20.04"), ("ubuntu", "22.04"), ("ubuntu", "24.04"), ("debian", "13")}

_RHEL_LIKE = {"rhel", "centos", "rocky", "almalinux", "ol"}
_SUSE_LIKE = {"sles", "sled", "opensuse-leap", "opensuse-tumbleweed", "opensuse"}


def parse_os_release(text: str) -> dict[str, str]:
    """Legge ID, ID_LIKE e VERSION_ID da /etc/os-release."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() in ("ID", "ID_LIKE", "VERSION_ID"):
            out[key.strip()] = value.strip().strip('"').strip("'").lower()
    return out


def os_family(info: dict[str, str]) -> str | None:
    os_id = info.get("ID", "")
    if os_id in ("debian", "ubuntu", "fedora"):
        return os_id
    if os_id in _RHEL_LIKE:
        return "rhel"
    if os_id in _SUSE_LIKE or os_id.startswith("opensuse"):
        return "suse"
    return None


def datastream_candidates(info: dict[str, str]) -> list[str]:
    """File SSG adatti a questo sistema, dal più specifico. Lista vuota se nessuno è noto."""
    os_id = info.get("ID", "")
    version = info.get("VERSION_ID", "")
    major = version.split(".")[0]
    names: list[str] = []
    fam = os_family(info)
    if fam == "ubuntu" and version:
        names.append(f"ssg-ubuntu{version.replace('.', '')}-ds.xml")
    elif fam == "debian" and major:
        names.append(f"ssg-debian{major}-ds.xml")
    elif fam == "rhel" and major:
        prefix = {"almalinux": "almalinux", "ol": "ol", "centos": "cs", "rocky": "rl"}.get(os_id)
        if prefix:
            names.append(f"ssg-{prefix}{major}-ds.xml")
        names.append(f"ssg-rhel{major}-ds.xml")
    elif fam == "fedora":
        names.append("ssg-fedora-ds.xml")
    elif fam == "suse":
        if os_id.startswith("opensuse"):
            names.append("ssg-opensuse-ds.xml")
        if major:
            names.append(f"ssg-sle{major}-ds.xml")
    return [f"{SSG_DIR}/{n}" for n in names]


def extract_xml_document(text: str) -> str:
    """Il primo documento XML contenuto in `text`, tagliato alla chiusura del suo elemento radice.

    oscap mescola sullo stdout righe leggibili e XML; qualsiasi testo dopo la chiusura della
    radice renderebbe l'XML illeggibile ("junk after document element").
    """
    start = text.find("<?xml")
    if start < 0:
        return text
    m = re.search(r"<(?![?!])([A-Za-z_][\w:.-]*)", text[start:])
    if not m:
        return text[start:]
    closing = f"</{m.group(1)}>"
    end = text.rfind(closing)
    return text[start:end + len(closing)] if end > start else text[start:]


class OpenSCAPTool(SecurityTool):
    name = "oscap"
    package = "openscap-scanner"
    # Arch e Alpine hanno oscap ma nessun contenuto SCAP per sé: valuterebbe il nulla.
    packages = {"debian": ["openscap-scanner"], "fedora": ["openscap-scanner"],
                "rhel": ["openscap-scanner"], "suse": ["openscap-utils"], "arch": None, "alpine": None}

    def unsupported_reason(self, host: HostInfo) -> str | None:
        if host.family in ("arch", "alpine"):
            return f"nessun contenuto SCAP disponibile per {host.pretty or host.family_label}"
        return super().unsupported_reason(host)

    def packages_for(self, host: HostInfo) -> list[str] | None:
        # Installare oscap e il contenuto SCAP sapendo già che il contenuto per questa
        # versione manca vorrebbe dire aggiungere e togliere pacchetti per niente. Se invece
        # oscap è già installato (con un contenuto aggiunto a mano), detect() lo trova e si usa.
        if (host.distro_id, host.version) in SSG_MISSING:
            return None
        return super().packages_for(host)

    def unavailable_message(self, host: HostInfo) -> str:
        if (host.distro_id, host.version) in SSG_MISSING:
            return (f"i repository di {host.pretty} non hanno il contenuto SCAP per questa versione "
                    "(si può installare a mano da github.com/ComplianceAsCode/content)")
        return super().unavailable_message(host)

    def __init__(self, profile: str | None = None) -> None:
        super().__init__()
        self._datastream: str | None = None
        self._os: dict[str, str] = {}
        self._profile_explicit = profile is not None
        self.profile = profile or DEFAULT_PROFILE

    def detect(self, executor: BaseExecutor) -> bool:
        path = find_tool(executor, "oscap")
        if not path:
            self.state = ToolState.ABSENT
            return False
        self._path = path
        self._locate_datastream(executor)
        self.state = ToolState.PRE_EXISTING
        return True

    def _read_os(self, executor: BaseExecutor) -> dict[str, str]:
        if not self._os:
            out, _, rc = executor.execute_command(["cat", "/etc/os-release"])
            self._os = parse_os_release(out) if rc == 0 else {}
        return self._os

    def _locate_datastream(self, executor: BaseExecutor) -> None:
        info = self._read_os(executor)
        # Sistema riconosciuto: solo il contenuto della sua versione.
        # Sistema sconosciuto (os-release illeggibile): elenco generico.
        candidates = datastream_candidates(info) if os_family(info) else list(SSG_PATHS)
        for ds in candidates:
            _, _, rc = executor.execute_command(["test", "-f", ds])
            if rc == 0:
                self._datastream = ds
                return

    def _describe_os(self) -> str:
        info = self._os
        if not info.get("ID"):
            return "questo sistema"
        return f"{info.get('ID')} {info.get('VERSION_ID', '')}".strip()

    def post_install(self, executor: BaseExecutor, tracker, sudo_ctx=None) -> None:
        """Dopo aver installato oscap, installa anche il contenuto SCAP (SSG).

        Senza datastream oscap non può valutare nulla. Il pacchetto SSG viene
        registrato nel tracker come "oscap-content:<pacchetto>" (una voce per
        candidato, così nessun pacchetto installato resta senza voce): così il cleanup lo rimuove
        insieme a oscap e non resta nulla sul target.
        """
        self._locate_datastream(executor)
        if self._datastream:
            return
        fam = os_family(self._read_os(executor))
        packages = SSG_PACKAGES_BY_OS.get(fam, SSG_PACKAGE_CANDIDATES) if fam else SSG_PACKAGE_CANDIDATES
        for pkg in packages:
            state = ensure_tool_installed(
                tracker, f"{SSG_TRACKER_KEY}:{pkg}", pkg, executor,
                allow_install=True, sudo_ctx=sudo_ctx,
            )
            if state in (InstallState.INSTALLED_BY_ASSESSOR, InstallState.PRE_EXISTING):
                self._locate_datastream(executor)
                if self._datastream:
                    return
        # nessun candidato ha prodotto un datastream: run() restituirà il marker
        # __NO_DATASTREAM__ e il report lo dirà esplicitamente.

    def _choose_profile(self, executor: BaseExecutor, prefix: list[str]) -> str:
        """Profilo da usare: quello richiesto, o un'alternativa se il datastream non ce l'ha."""
        if self._profile_explicit:
            return self.profile
        out, _, rc = executor.execute_command(
            prefix + [self._path, "info", "--profiles", self._datastream])
        available = {line.split(":", 1)[0].strip() for line in (out or "").splitlines() if line.strip()}
        if rc != 0 or not available or self.profile in available:
            return self.profile
        for p in PROFILE_FALLBACKS:
            if p in available:
                return p
        return sorted(available)[0]

    def run(self, executor: BaseExecutor, target: str | None = None) -> str:
        if not self._datastream:
            return f"__NO_DATASTREAM__\n{self._describe_os()}"

        # Come root (o con sudo -n) oscap legge anche i file protetti:
        # senza, molte regole risultano errate o non verificabili.
        prefix = privileged_prefix(executor)
        profile = self._choose_profile(executor, prefix)

        cmd = prefix + [
            self._path, "xccdf", "eval",
            "--profile", profile,
            "--results", "-",
            self._datastream,
        ]
        out, err, rc = executor.execute_command(cmd)
        if rc not in (0, 2) and not out:
            return err or ""
        # Con "--results -" oscap scrive sullo stdout il testo leggibile delle regole e
        # l'XML dei risultati: al parser serve solo il documento XML, senza nulla prima o dopo.
        return extract_xml_document(out or "")

    def parse(self, raw_output: str) -> list[Finding]:
        return parse_openscap(raw_output)
