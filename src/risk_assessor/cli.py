"""Riga di comando di WatchDog: risk assessment per Linux (ogni distribuzione) e macOS."""
from __future__ import annotations
import argparse
import time
from types import SimpleNamespace
import getpass
import os
import sys

# Forza UTF-8 su stdout/stderr (Windows usa cp1252)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
from argparse import Namespace
from datetime import datetime, timezone
from pathlib import Path

from risk_assessor.models import Assessment, Finding, Severity
from risk_assessor.sanitize import clean_text
from risk_assessor.interactive import DEFAULT_FORMATS, VALID_FORMATS, MenuApp, ScanError, Settings
from risk_assessor.reports.json_report import generate_json_report
from risk_assessor.reports.markdown_report import generate_markdown_report
from risk_assessor.reports.html_report import generate_html_report
from risk_assessor.risk.compare import compare, find_previous, load_assessment, report_dir_prefix
from risk_assessor.integrations.polyscan import PolyscanReportError
from risk_assessor.integrations.wazuh import append_wazuh_log, write_wazuh_report
from risk_assessor.integrations.polyscan import import_report as import_polyscan
from risk_assessor.risk.attack import ATTACK_VERSION, Coverage, load_layer, technique_rows
from risk_assessor.fleet import MAX_PARALLEL, FleetHost, HostResult, InventoryError, load_inventory, run_fleet
from risk_assessor.reports.fleet_report import generate_fleet_reports
from risk_assessor.reports.console_report import render_console_summary
from risk_assessor.config import Config, load_config
from risk_assessor.reports.progress import ProgressReporter, NullProgress
from risk_assessor.executor import (
    BaseExecutor, LocalExecutor, SSHExecutor, SSHConnectionError,
)
from risk_assessor.host import HostInfo, host_info

from risk_assessor.collectors.linux import LinuxCollector
from risk_assessor.collectors.users import UsersCollector
from risk_assessor.collectors.ssh_config import SSHConfigCollector
from risk_assessor.collectors.auth_policy import AuthPolicyCollector
from risk_assessor.collectors.kernel import KernelCollector
from risk_assessor.collectors.logging_audit import LoggingCollector
from risk_assessor.collectors.persistence import PersistenceCollector
from risk_assessor.collectors.updates import UpdatesCollector
from risk_assessor.collectors.firewall import FirewallCollector
from risk_assessor.collectors.services import ServicesCollector
from risk_assessor.collectors.filesystem import FilesystemCollector
from risk_assessor.collectors.packages import PackagesCollector
from risk_assessor.collectors.protections import ProtectionsCollector
from risk_assessor.collectors.macos_extra import (
    MacFilesystemCollector, MacKernelCollector, MacLoggingCollector, MacPackagesCollector,
)
from risk_assessor.collectors.macos import (
    MacAuthPolicyCollector, MacFirewallCollector, MacPersistenceCollector, MacProtectionsCollector,
    MacServicesCollector, MacSSHCollector, MacSystemCollector, MacUpdatesCollector, MacUsersCollector,
)

from risk_assessor.tools.manager import ToolManager
from risk_assessor.tools.nmap import NmapTool
from risk_assessor.external_scan import run_external_scan, valid_external_host
from risk_assessor.tools.rkhunter import RkhunterTool
from risk_assessor.tools.chkrootkit import ChkrootkitTool
from risk_assessor.tools.lynis import LynisTool
from risk_assessor.tools.clamav import ClamAVTool
from risk_assessor.tools.aide import AideTool
from risk_assessor.tools.debsecan import DebsecanTool
from risk_assessor.tools.debsums import DebsumsTool
from risk_assessor.tools.trivy import TrivyTool
from risk_assessor.tools.openscap import OpenSCAPTool
from risk_assessor.reports.watchdog_banner import print_banner as print_watchdog_banner

# Mappa: nome tool → coppia (classe, kwargs) per la tool_list
# Ordinati per tempo atteso (veloci → lenti) così l'utente vede
# subito i primi finding nella progress bar
_TOOL_FACTORIES = [
    ("nmap",       lambda full_scan: NmapTool()),        # ~7s
    ("debsecan",   lambda full_scan: DebsecanTool()),    # ~15s
    ("debsums",    lambda full_scan: DebsumsTool()),     # ~40s
    ("trivy",      lambda full_scan: TrivyTool()),       # ~40s (più il database al primo avvio)
    ("openscap",   lambda full_scan: OpenSCAPTool()),    # ~30s
    ("chkrootkit", lambda full_scan: ChkrootkitTool()),  # ~45s
    ("aide",       lambda full_scan: AideTool()),        # ~60s
    ("lynis",      lambda full_scan: LynisTool()),       # ~90s
    ("clamav",     lambda full_scan: ClamAVTool(full_system_scan=full_scan)),  # ~120s
    ("rkhunter",   lambda full_scan: RkhunterTool()),    # ~220s
]

# Controlli nativi: nome → classe per piattaforma ("linux", "darwin").
# Un nome senza versione per la piattaforma del target viene saltato e il report lo
# elenca tra i controlli non applicabili.
_COLLECTOR_FACTORIES = [
    ("linux",      {"linux": LinuxCollector, "darwin": MacSystemCollector}),
    ("users",      {"linux": UsersCollector, "darwin": MacUsersCollector}),
    ("ssh_config", {"linux": SSHConfigCollector, "darwin": MacSSHCollector}),
    ("firewall",   {"linux": FirewallCollector, "darwin": MacFirewallCollector}),
    ("services",   {"linux": ServicesCollector, "darwin": MacServicesCollector}),
    ("filesystem", {"linux": FilesystemCollector, "darwin": MacFilesystemCollector}),
    ("packages",   {"linux": PackagesCollector, "darwin": MacPackagesCollector}),   # macOS: Homebrew
    ("auth_policy", {"linux": AuthPolicyCollector, "darwin": MacAuthPolicyCollector}),
    ("kernel",     {"linux": KernelCollector, "darwin": MacKernelCollector}),
    ("logging",    {"linux": LoggingCollector, "darwin": MacLoggingCollector}),
    ("updates",    {"linux": UpdatesCollector, "darwin": MacUpdatesCollector}),
    ("persistence", {"linux": PersistenceCollector, "darwin": MacPersistenceCollector}),
    ("protections", {"linux": ProtectionsCollector, "darwin": MacProtectionsCollector}),
]


def _platform_key(info: HostInfo) -> str:
    """Piattaforma per scegliere i controlli: un target non riconosciuto è trattato come Linux."""
    return "darwin" if info.is_macos else "linux"


def _known_tools() -> list[str]:
    return [n for n, _ in _COLLECTOR_FACTORIES] + [n for n, _ in _TOOL_FACTORIES]


def _split_list(value: str) -> list[str]:
    """'a, B ,c' -> ['a', 'b', 'c']: spazi e maiuscole non contano."""
    return [v.strip().lower() for v in (value or "").split(",") if v.strip()]


def _unknown_tools(requested: list[str]) -> list[str]:
    known = set(_known_tools()) | {"all"}
    return [t for t in requested if t not in known]


def _selected(name: str, tools: list[str]) -> bool:
    """Ritorna True se il collector/tool va eseguito."""
    return name in tools or "all" in tools


# Tool opzionali: fuori dalla scansione completa finché non li si aggiunge
# (config.yaml, --with, menu "Strumenti opzionali"). Nome, etichetta, perché è opzionale.
OPTIONAL_TOOLS = [
    ("trivy", "Trivy", "vulnerabilità note dei pacchetti; scarica un binario verificato e un "
                       "database da internet (sul target)"),
    ("aide", "AIDE", "integrità dei file rispetto a una baseline; la prima volta crea solo la "
                     "baseline e può richiedere molto tempo"),
    ("rkhunter", "rkhunter", "rootkit; non più mantenuto (2018), lento (minuti) e con molti "
                             "falsi positivi: per i rootkit basta chkrootkit"),
]


def _expand_tools(tools: list[str], cfg: Config, extra=()) -> list[str]:
    """Applica config.yaml alla selezione.

    - "all" viene espanso in tutti i collector/tool NON disabilitati nel config, più gli
      eventuali tool opzionali aggiunti (`extra`), nell'ordine di esecuzione;
    - una lista esplicita (--tools a,b) ha precedenza sul config e resta com'è.
    """
    if "all" not in tools:
        return tools
    known = [n for n, _ in _COLLECTOR_FACTORIES] + [n for n, _ in _TOOL_FACTORIES]
    return [n for n in known if cfg.tool_cfg(n).enabled or n in extra]


def _load_cfg(path: str | None) -> Config:
    """Carica il config; avvisa se un file indicato esplicitamente non esiste."""
    if path and path != "config.yaml" and not Path(path).exists():
        print(f"ATTENZIONE: file di configurazione '{path}' non trovato, "
              "uso i valori di default.", file=sys.stderr)
    return load_config(path)


def _run_assessment_core(
    executor: BaseExecutor,
    target: str,
    mode: str,
    tools: list[str],
    keep_tools: bool,
    full_clamav_scan: bool,
    sudo_password: str | None,
    no_install: bool,
    progress=None,
    clamav_paths: list[str] | None = None,
    external_host: str | None = None,
    allow_epel: bool = False,
) -> Assessment:
    """Logica condivisa tra local e SSH.

    Esegue tutti i collector e i tool esterni tramite un Executor già creato.
    """
    if progress is None:
        progress = NullProgress()

    n_collectors = sum(1 for name, _ in _COLLECTOR_FACTORIES if _selected(name, tools))
    n_tools = sum(1 for name, _ in _TOOL_FACTORIES if _selected(name, tools))

    # Per SSH lo step "Connessione SSH" è già stato consumato da _run_ssh_assessment.
    # Per local, lo step "Inizializzazione assessment" lo facciamo qui sotto.
    if progress.total == 0:
        extra_init = 0 if mode == "ssh" else 1
        progress.total = extra_init + 1 + n_collectors + n_tools + (1 if external_host else 0) + 1

    a = Assessment(target=target, mode=mode)
    a.tools_used = tools

    # Step iniziale (solo local; SSH ha già fatto "Connessione SSH")
    if mode != "ssh":
        progress.start_step("Inizializzazione assessment")
        progress.ok()

    # Step 1: che sistema è? (una sola richiesta; il risultato lo usano tutti i controlli)
    progress.start_step("Rilevamento del sistema")
    info = host_info(executor)
    platform = _platform_key(info)
    a.metadata["host"] = info.to_dict()
    if info.commands is None:
        progress.fail("sistema non riconosciuto: si procede con i controlli Linux")
        a.errors.append("rilevamento del sistema non riuscito: i risultati potrebbero essere incompleti")
    else:
        details = ", ".join(x for x in (info.pretty, info.package_manager or "nessun gestore pacchetti",
                                        f"init {info.init}", info.container and f"container {info.container}") if x)
        progress.ok(f"({details})")
    not_applicable: dict[str, str] = {}

    # Step 2: collector nativi
    durations: dict[str, dict[str, float]] = {}     # secondi per controllo (nel report)
    a.metadata["durations"] = durations
    for name, classes in _COLLECTOR_FACTORIES:
        if not _selected(name, tools):
            continue
        progress.start_step(f"Collector: {name}")
        cls = classes.get(platform)
        if cls is None:
            reason = f"non applicabile su {info.platform_label}"
            not_applicable[name] = reason
            progress.skip(reason)
            continue
        started = time.monotonic()
        try:
            findings = cls().collect(executor)
            a.findings.extend(findings)
            progress.ok(f"({len(findings)} finding)")
        except Exception as e:
            # Un controllo andato in errore deve risultare nel report, non sparire.
            a.errors.append(clean_text(f"{name}: errore interno del controllo ({type(e).__name__}: {e})"))
            progress.fail(f"{type(e).__name__}: {e}")
        durations[name] = {"run": round(time.monotonic() - started, 1)}

    # Step 3: tool esterni
    tool_list = []
    config_name: dict[str, str] = {}   # nome del binario (es. clamscan) -> nome del controllo (clamav)
    for name, factory in _TOOL_FACTORIES:
        if _selected(name, tools):
            tool = factory(full_clamav_scan)
            if clamav_paths and isinstance(tool, ClamAVTool):
                tool.scan_paths = list(clamav_paths)
            tool_list.append(tool)
            config_name[tool.name] = name

    if tool_list:
        mgr = ToolManager(
            tool_list,
            allow_install=not no_install,
            keep_tools=keep_tools,
            sudo_password=sudo_password,
            allow_epel=allow_epel,
        )
        a.findings.extend(mgr.run_all(executor, target="127.0.0.1", progress=progress))
        for tool_name, err in mgr.errors.items():
            a.errors.append(clean_text(f"{config_name.get(tool_name, tool_name)}: {err}"))
        for tool_name, reason in mgr.not_applicable.items():
            not_applicable[config_name.get(tool_name, tool_name)] = clean_text(reason)
        for tool_name, times in mgr.durations.items():
            durations[config_name.get(tool_name, tool_name)] = times
        if mgr.cleanup_seconds:
            a.metadata["cleanup_seconds"] = mgr.cleanup_seconds
        if mgr.cleanup_report is not None:
            a.cleanup_status = mgr.cleanup_report.summary()
        else:
            a.cleanup_status = "SKIPPED (keep_tools)"
    else:
        # Se nessun tool, salta gli step (progress.total era già contato, ma va bene)
        pass

    # Scansione Nmap dall'esterno (dal PC dell'operatore verso l'host da valutare)
    if external_host:
        progress.start_step("Nmap dall'esterno")
        internal = next((t.open_ports for t in tool_list if isinstance(t, NmapTool)), None)
        ext_findings, ext_err = run_external_scan(external_host, internal)
        a.findings.extend(ext_findings)
        if ext_err:
            a.errors.append(ext_err)      # non eseguita: non va elencata tra i controlli fatti
            progress.fail(ext_err)
        else:
            if "nmap_external" not in a.tools_used:
                a.tools_used = list(a.tools_used) + ["nmap_external"]
            progress.ok(f"({len(ext_findings)} finding)")

    # Nel report "Cosa è stato controllato" elenca solo ciò che aveva senso eseguire;
    # il resto compare a parte, con il motivo.
    if not_applicable:
        a.metadata["not_applicable"] = not_applicable
        a.tools_used = [t for t in a.tools_used if t not in not_applicable]

    # Step finale: analisi e report
    progress.start_step("Analisi e generazione report")

    if not a.findings:
        a.add_finding(Finding(
            title="Nessun controllo eseguito",
            category="info",
            severity=Severity.INFO,
            description="Nessun collector ha prodotto risultati.",
            evidence="",
            recommendation="Verificare la configurazione dei tool.",
            source="cli",
        ))

    a.finish()
    progress.ok(f"(score {a.risk_score}/100 {a.risk_level})")
    return a


def _run_assessment(
    target: str,
    mode: str,
    tools: list[str],
    keep_tools: bool = False,
    full_clamav_scan: bool = False,
    sudo_password: str | None = None,
    no_install: bool = False,
    progress=None,
    clamav_paths: list[str] | None = None,
    allow_epel: bool = False,
) -> Assessment:
    """Assessment locale."""
    ex = LocalExecutor()
    try:
        return _run_assessment_core(
            ex, target, mode, tools,
            keep_tools, full_clamav_scan, sudo_password, no_install,
            progress=progress, clamav_paths=clamav_paths, allow_epel=allow_epel,
        )
    finally:
        ex.close()


def _run_ssh_assessment(
    host: str,
    user: str,
    port: int,
    key: str | None,
    tools: list[str],
    keep_tools: bool = False,
    full_clamav_scan: bool = False,
    password: str | None = None,
    sudo_password: str | None = None,
    no_install: bool = False,
    progress=None,
    clamav_paths: list[str] | None = None,
    accept_new_host_key: bool = False,
    external_scan: bool = False,
    allow_epel: bool = False,
) -> Assessment:
    """Assessment remoto via SSH.

    Solleva SSHConnectionError se la connessione non riesce: meglio fermarsi che
    produrre un report "valido" costruito su comandi tutti falliti.
    """
    target = f"{host}:{port}"
    if key:
        key = os.path.expanduser(key)

    if progress is not None:
        progress.start_step("Connessione SSH")

    ex = SSHExecutor(
        host=host, user=user, port=port,
        key_file=key, password=password,
        accept_new_host_key=accept_new_host_key,
    )
    try:
        ex.connect()
    except SSHConnectionError as e:
        ex.close()
        if progress is not None:
            progress.fail(str(e))
        raise
    if progress is not None:
        progress.ok()

    try:
        return _run_assessment_core(
            ex, target, "ssh", tools,
            keep_tools, full_clamav_scan, sudo_password, no_install,
            progress=progress, clamav_paths=clamav_paths,
            external_host=host if external_scan else None, allow_epel=allow_epel,
        )
    finally:
        ex.close()


def _apply_imports(a: Assessment, imports: list) -> None:
    """Aggiunge all'assessment i risultati importati (polyscan) e ricalcola il rischio."""
    if not imports:
        return
    for findings, errors, origin in imports:
        a.findings.extend(findings)
        a.errors.extend(errors)
        a.metadata.setdefault("imported", []).append(origin)
    if "polyscan" not in a.tools_used:
        a.tools_used.append("polyscan")
    a.finish()


def _previous_for(a: Assessment, base_dir: Path, compare_with: str | None, auto: bool) -> dict | None:
    """Assessment precedente da confrontare: quello indicato, o l'ultimo dello stesso target."""
    if compare_with:
        data = load_assessment(Path(compare_with))
        if data is None:
            print(f"ATTENZIONE: '{compare_with}' non è un assessment.json leggibile: "
                  "confronto non eseguito.", file=sys.stderr)
        elif clean_text(str(data.get("target", ""))) != a.target:
            print(f"ATTENZIONE: '{compare_with}' è di un altro obiettivo ({clean_text(str(data.get('target')))}, "
                  f"non {a.target}): confronto non eseguito.", file=sys.stderr)
            return None
        return data
    return find_previous(base_dir, a.target, a.started_at) if auto else None


def _write_reports(a: Assessment, base_dir: Path, formats: list[str],
                   compare_with: str | None = None, auto_compare: bool = True,
                   attack_layer: Coverage | None = None, wazuh_log: str | None = None) -> list[Path]:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out_dir = base_dir / f"{report_dir_prefix(a.target)}{ts}"
    previous = _previous_for(a, base_dir, compare_with, auto_compare)
    cmp = compare(a, previous)
    if cmp is not None:
        a.metadata["comparison"] = cmp.to_dict()
    system = str((a.metadata.get("host") or {}).get("system", ""))
    rows = technique_rows(a.findings, attack_layer, system)
    if rows:
        a.metadata["attack"] = {"version": ATTACK_VERSION,
                                "layer": attack_layer.name if attack_layer else None,
                                "layer_platforms": list(attack_layer.platforms) if attack_layer else [],
                                "techniques": rows}
    written: list[Path] = []
    if "json" in formats:
        written.append(generate_json_report(a, out_dir))
    if "md" in formats or "markdown" in formats:
        written.append(generate_markdown_report(a, out_dir))
    if "html" in formats:
        written.append(generate_html_report(a, out_dir, previous))
    if "wazuh" in formats:
        written.append(write_wazuh_report(a, out_dir))
    if wazuh_log:
        try:
            written.append(append_wazuh_log(a, wazuh_log))
        except OSError as e:
            print(f"ATTENZIONE: impossibile scrivere il log per Wazuh '{wazuh_log}': {e}", file=sys.stderr)
    return written


def _print_ssh_error(e: Exception) -> None:
    """Messaggio chiaro per un fallimento di connessione SSH."""
    print(f"\nERRORE: connessione SSH fallita: {e}", file=sys.stderr)
    if "known_hosts" in str(e):
        print("  La chiave host del server è sconosciuta. Verificane l'impronta e "
              "aggiungila (ssh-keyscan),\n  oppure usa --accept-new-host-key "
              "se ti fidi della rete.", file=sys.stderr)
    print("  Nessun report generato: l'assessment non è stato eseguito.",
          file=sys.stderr)


# Durata indicativa (secondi) di ogni tool esterno, per la stima mostrata dal menu.
_TOOL_ETA = {
    "nmap": 7, "nmap_external": 20, "debsecan": 15, "debsums": 40, "trivy": 40, "openscap": 30, "chkrootkit": 45,
    "aide": 60, "lynis": 90, "clamav": 120, "rkhunter": 220,
}
_COLLECTOR_ETA = 4
_FULL_CLAMAV_ETA = 3600


class _CliBackend:
    """Collega il menu interattivo (interactive.py) alle funzioni di esecuzione di questo modulo."""

    def __init__(self) -> None:
        self.config_path = "config.yaml"
        self.config_loaded = Path(self.config_path).exists()
        self.cfg = _load_cfg(None)

    def defaults(self) -> Settings:
        formats: list[str] = []
        for f in self.cfg.report.formats:
            f = "md" if f == "markdown" else f
            if f in VALID_FORMATS and f not in formats:
                formats.append(f)
        return Settings(
            allow_install=True,
            keep_tools=not self.cfg.cleanup.enabled,
            full_clamav=self.cfg.tool_cfg("clamav").full_scan,
            formats=formats or list(DEFAULT_FORMATS),
            output_dir=self.cfg.report.output_dir,
            allow_epel=self.cfg.install.epel,
        )

    def checks(self) -> list[tuple[str, str]]:
        return ([(n, "native") for n, _ in _COLLECTOR_FACTORIES]
                + [(n, "tool") for n, _ in _TOOL_FACTORIES])

    def _enabled(self, names: list[str]) -> list[str]:
        return [n for n in names if self.cfg.tool_cfg(n).enabled]

    def optional_tools(self) -> list[tuple[str, str, str, bool]]:
        """(nome, etichetta, nota, già incluso da config.yaml) per il menu."""
        return [(n, label, note, self.cfg.tool_cfg(n).enabled) for n, label, note in OPTIONAL_TOOLS]

    def presets(self, extras=()) -> list[tuple[str, str, list[str]]]:
        native = [n for n, _ in _COLLECTOR_FACTORIES]
        external = [n for n, _ in _TOOL_FACTORIES]
        added = f" + {', '.join(extras)}" if extras else ""
        return [
            ("Scansione completa", "tutto ciò che è abilitato in config.yaml" + added,
             _expand_tools(["all"], self.cfg, extras)),
            ("Solo controlli nativi", "nessuna installazione", self._enabled(native)),
            ("Hardening e persistenza", "password, kernel, log, aggiornamenti, persistenza, protezioni",
             self._enabled(["ssh_config", "auth_policy", "kernel", "logging", "updates", "persistence",
                            "protections"])),
            ("Solo tool esterni", "Nmap, Lynis, chkrootkit, OpenSCAP, ClamAV…" + added,
             [n for n in external if self.cfg.tool_cfg(n).enabled or n in extras]),
            ("Nmap", "porte e servizi aperti", ["nmap"]),
            ("Lynis", "audit generale", ["lynis"]),
            ("Rootkit", "rkhunter + chkrootkit", ["rkhunter", "chkrootkit"]),
            ("OpenSCAP", "conformità a profili standard", ["openscap"]),
            ("ClamAV", "malware", ["clamav"]),
            ("Integrità e vulnerabilità", "debsums + debsecan", ["debsums", "debsecan"]),
            ("AIDE", "integrità con baseline (lento: opzionale)", ["aide"]),
            ("Trivy", "vulnerabilità dei pacchetti (richiede internet)", ["trivy"]),
        ]

    def estimate(self, tools: list[str], settings: Settings,
                 external: bool = False) -> tuple[int, int]:
        n_coll = sum(1 for n, _ in _COLLECTOR_FACTORIES if _selected(n, tools))
        n_tools = sum(1 for n, _ in _TOOL_FACTORIES if _selected(n, tools))
        seconds = n_coll * _COLLECTOR_ETA
        for n, _ in _TOOL_FACTORIES:
            if _selected(n, tools):
                seconds += _FULL_CLAMAV_ETA if (n == "clamav" and settings.full_clamav) else _TOOL_ETA.get(n, 60)
        if external:
            seconds += _TOOL_ETA["nmap_external"]
        return 1 + 1 + n_coll + n_tools + (1 if external else 0) + 1, seconds

    def run_scan(self, plan) -> Assessment:
        s = plan.settings
        steps, _ = self.estimate(plan.tools, s, external=plan.external_scan)
        progress = ProgressReporter(enabled=True, total_steps=steps)
        clamav_paths = self.cfg.tool_cfg("clamav").scan_paths
        progress.banner(f"Assessment {'SSH: ' + plan.target if plan.mode == 'ssh' else 'locale'}"
                        f" · {plan.label} ({steps} step)")
        progress.banner("")
        common = dict(
            tools=plan.tools, keep_tools=s.keep_tools, full_clamav_scan=s.full_clamav,
            sudo_password=plan.sudo_password, no_install=not s.allow_install,
            progress=progress, clamav_paths=clamav_paths, allow_epel=s.allow_epel,
        )
        try:
            if plan.mode == "ssh":
                p = plan.ssh
                return _run_ssh_assessment(
                    host=p.host, user=p.user, port=p.port, key=p.key,
                    password=plan.ssh_password, accept_new_host_key=p.accept_new_host_key,
                    external_scan=plan.external_scan,
                    **common,
                )
            return _run_assessment("localhost", "local", **common)
        except SSHConnectionError as e:
            progress.blank()
            _print_ssh_error(e)
            raise ScanError(str(e)) from e

    def _layer(self, settings: Settings) -> Coverage | None:
        if not settings.attack_layer:
            return None
        try:
            return load_layer(settings.attack_layer)
        except ValueError as e:
            print(f"ATTENZIONE: {e}: copertura ATT&CK non indicata.", file=sys.stderr)
            return None

    def write_reports(self, assessment: Assessment, settings: Settings) -> list[Path]:
        imports = []
        for path in settings.polyscan_reports:
            try:
                imports.append(import_polyscan(path))
            except PolyscanReportError as e:
                print(f"ATTENZIONE: {e}: rapporto non importato.", file=sys.stderr)
        _apply_imports(assessment, imports)
        return _write_reports(assessment, Path(settings.output_dir), settings.formats,
                              attack_layer=self._layer(settings), wazuh_log=settings.wazuh_log or None)

    def run_fleet(self, inventory: str, tools: list[str], settings: Settings, parallel: int) -> list[Path]:
        args = SimpleNamespace(inventory=inventory, no_install=not settings.allow_install, compare=None,
                               no_compare=False, accept_new_host_key=False, ask_sudo_password=False,
                               wazuh_log=settings.wazuh_log or None, parallel=parallel)
        code, written = _fleet_run(args, self.cfg, tools, tuple(settings.extra_tools), settings.keep_tools,
                                   settings.full_clamav, self.cfg.tool_cfg("clamav").scan_paths,
                                   settings.formats, Path(settings.output_dir), settings.allow_epel,
                                   self._layer(settings))
        if code in (1, 130):
            raise ScanError("fleet non completato")
        return written

    def compare_reports(self, old: Path, new: Path) -> None:
        _compare_command(str(old), str(new))

    def show_summary(self, assessment: Assessment, paths: list[Path]) -> None:
        render_console_summary(assessment, report_paths=paths)


def run_menu() -> int:
    return MenuApp(_CliBackend(), banner_fn=print_watchdog_banner).run()


_SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
FAIL_ON_EXIT = 4


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    """Aggiunge argomenti comuni a local e ssh."""
    parser.add_argument("--tools", default=",".join(n for n, _ in _COLLECTOR_FACTORIES),
                        help="Controlli e tool separati da virgola (default: tutti i controlli nativi, "
                             "senza installare nulla). Nomi: " + ", ".join(_known_tools()))
    parser.add_argument("--all", help="Tutti i controlli e i tool abilitati in config.yaml", action="store_true")
    parser.add_argument("--with", dest="with_tools", default="", metavar="TOOL,...",
                        help="Con --all: aggiunge tool opzionali ("
                             + ", ".join(n for n, _, _ in OPTIONAL_TOOLS) + ")")
    parser.add_argument("--format", default=None,
                        help="Formati report separati da virgola: json, md, html, wazuh "
                             "(default: da config.yaml, altrimenti json,md,html)")
    parser.add_argument("--keep-tools", action="store_true",
                        help="Non rimuovere i tool installati durante l'assessment")
    parser.add_argument("--full-clamav-scan", action="store_true",
                        help="ClamAV scansiona l'intero filesystem (lento)")
    parser.add_argument("--ask-sudo-password", action="store_true",
                        help="Chiedi la password sudo se NOPASSWD non è configurato")
    parser.add_argument("--no-install", action="store_true",
                        help="Non installare/rimuovere tool esterni (solo check)")
    parser.add_argument("--enable-epel", action="store_true",
                        help="RHEL, Rocky, Alma...: attiva il repository EPEL se serve a un tool "
                             "(Lynis, rkhunter, ClamAV) e lo rimuove a fine scansione")
    parser.add_argument("--compare", metavar="REPORT",
                        help="Confronta con questo assessment.json (o la sua cartella) invece che "
                             "con l'ultima scansione dello stesso target")
    parser.add_argument("--no-compare", action="store_true",
                        help="Non confrontare con le scansioni precedenti")
    parser.add_argument("--import-polyscan", action="append", default=[], metavar="FILE",
                        help="Aggiunge al report i risultati di polyscan (rapporto JSON di 'polyscan scan' o "
                             "'polyscan dast'): le applicazioni del server entrano nello stesso assessment. Ripetibile")
    parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"],
                        help=f"Esce con codice {FAIL_ON_EXIT} se c'è almeno un finding di questa severità o più "
                             "grave (per bloccare una pipeline)")
    parser.add_argument("--wazuh-log", metavar="FILE",
                        help="Aggiunge i risultati (righe JSON) a questo file, letto da Wazuh: "
                             "vedi integrations/wazuh/")
    parser.add_argument("--attack-layer", metavar="FILE",
                        help="Layer di ATT&CK Navigator con la copertura di rilevamento (per esempio quello "
                             "di detection-engineering-lab): il report dice quali problemi non sarebbero rilevati")
    parser.add_argument("--config", default="config.yaml",
                        help="File di configurazione YAML (default: config.yaml)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="risk_assessor",
        description="WatchDog: risk assessment di sicurezza per Linux (ogni distribuzione) e macOS",
    )
    sub = p.add_subparsers(dest="command")

    lp = sub.add_parser("local", help="Assessment locale")
    _add_common_args(lp)

    sp = sub.add_parser("ssh", help="Assessment via SSH")
    sp.add_argument("--host", required=True)
    sp.add_argument("--user", required=True)
    sp.add_argument("--port", type=int, default=22)
    sp.add_argument("--key")
    sp.add_argument("--ask-password", action="store_true",
                    help="Chiedi la password SSH interattivamente (nascosta)")
    sp.add_argument("--password-env", metavar="VAR",
                    help="Leggi la password SSH dalla variabile d'ambiente VAR")
    sp.add_argument("--accept-new-host-key", action="store_true",
                    help="Accetta automaticamente chiavi host SSH sconosciute "
                         "(meno sicuro: usalo solo su reti fidate)")
    sp.add_argument("--external-scan", action="store_true",
                    help="Aggiunge una scansione Nmap dall'esterno: dal tuo PC verso l'host. "
                         "Richiede nmap installato qui e l'autorizzazione a scansionare l'host")
    _add_common_args(sp)

    fp = sub.add_parser("fleet", help="Assessment di più host via SSH da un inventario YAML")
    fp.add_argument("--inventory", required=True, metavar="FILE",
                    help="Inventario YAML degli host (vedi docs/inventory.example.yaml)")
    fp.add_argument("--parallel", type=int, default=4,
                    help=f"Host analizzati contemporaneamente (default 4, massimo {MAX_PARALLEL})")
    fp.add_argument("--accept-new-host-key", action="store_true",
                    help="Accetta chiavi host sconosciute per tutti gli host (solo reti fidate)")
    _add_common_args(fp)

    cp = sub.add_parser("compare", help="Confronta due report già fatti (assessment.json o cartelle)")
    cp.add_argument("old", help="Report precedente")
    cp.add_argument("new", help="Report più recente")

    return p


def _prompt_sudo_password_if_needed(args) -> str | None:
    """Chiede la password sudo se --ask-sudo-password è attivo. None se annullato."""
    if not getattr(args, "ask_sudo_password", False):
        return None
    from risk_assessor.lifecycle.sudo import prompt_sudo_password
    return prompt_sudo_password()


def _resolve_ssh_password(args) -> str | None:
    """Risolve la password SSH da prompt o env. None se non richiesta."""
    if args.ask_password:
        try:
            return getpass.getpass("SSH password: ")
        except (KeyboardInterrupt, EOFError):
            return None
    if args.password_env:
        pw = os.environ.get(args.password_env)
        if pw is None:
            print(f"ERRORE: variabile d'ambiente '{args.password_env}' non impostata.",
                  file=sys.stderr)
            return None
        return pw
    return None


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        return run_menu()
    args: Namespace = build_parser().parse_args(argv)

    if args.command in ("local", "ssh", "fleet"):
        # config.yaml: i valori passati da CLI hanno la precedenza
        cfg = _load_cfg(args.config)
        requested = ["all"] if args.all else _split_list(args.tools)
        bad = _unknown_tools(requested)
        if bad or not requested:
            print(f"ERRORE: controllo o tool sconosciuto: {', '.join(bad) or '(vuoto)'}.\n"
                  f"Nomi validi: {', '.join(_known_tools())}, oppure --all.", file=sys.stderr)
            return 1
        extras = _split_list(getattr(args, "with_tools", ""))
        bad_extra = [t for t in extras if t not in {n for n, _ in _TOOL_FACTORIES}]
        if bad_extra:
            print(f"ERRORE: --with accetta solo tool esterni: {', '.join(bad_extra)}.", file=sys.stderr)
            return 1
        if extras and not args.all:
            requested = requested + [t for t in extras if t not in requested]
        tools = _expand_tools(requested, cfg, extras)
        keep_tools = args.keep_tools or not cfg.cleanup.enabled
        full_clamav_scan = args.full_clamav_scan or cfg.tool_cfg("clamav").full_scan
        clamav_paths = cfg.tool_cfg("clamav").scan_paths
        formats = ["md" if f == "markdown" else f
                   for f in _split_list(args.format or ",".join(cfg.report.formats))]
        bad_formats = [f for f in formats if f not in VALID_FORMATS]
        if bad_formats or not formats:
            print(f"ERRORE: formato non supportato: {', '.join(bad_formats) or '(vuoto)'}.\n"
                  f"Formati ammessi: {', '.join(VALID_FORMATS)}.", file=sys.stderr)
            return 1
        out_dir = Path(cfg.report.output_dir)
        allow_epel = bool(args.enable_epel or cfg.install.epel)
        imports = []
        for path in args.import_polyscan:
            try:
                imports.append(import_polyscan(path))
            except PolyscanReportError as e:
                print(f"ERRORE: {e}", file=sys.stderr)
                return 1
        layer = None
        if args.attack_layer:
            try:
                layer = load_layer(args.attack_layer)
            except ValueError as e:
                print(f"ERRORE: {e}", file=sys.stderr)
                return 1

    if args.command == "local":
        sudo_password = _prompt_sudo_password_if_needed(args)
        if getattr(args, "ask_sudo_password", False) and sudo_password is None:
            print("\nOperazione annullata.", file=sys.stderr)
            return 1

        n_coll = sum(1 for name, _ in _COLLECTOR_FACTORIES if _selected(name, tools))
        n_tools = sum(1 for name, _ in _TOOL_FACTORIES if _selected(name, tools))
        total = 1 + 1 + n_coll + n_tools + 1  # init + sistema + coll + tools + report
        progress = ProgressReporter(enabled=True, total_steps=total)
        progress.banner("")
        progress.banner("Assessment locale")
        progress.banner(f"Tipo: {', '.join(requested)} ({total} step)")
        progress.banner("")
        try:
            a = _run_assessment(
                "localhost", "local", tools,
                keep_tools=keep_tools,
                full_clamav_scan=full_clamav_scan,
                sudo_password=sudo_password,
                no_install=args.no_install,
                progress=progress,
                clamav_paths=clamav_paths,
                allow_epel=allow_epel,
            )
        except KeyboardInterrupt:
            progress.blank()
            progress.banner("\n  Interrotto dall'utente.")
            return 130
        sudo_password = None  # wipe
        _apply_imports(a, imports)
        written = _write_reports(a, out_dir, formats, args.compare, not args.no_compare, layer,
                                 args.wazuh_log)
        render_console_summary(a, report_paths=written)
        return _fail_on_exit(args.fail_on, [a])

    if args.command == "ssh":
        password = _resolve_ssh_password(args)
        if (args.ask_password or args.password_env) and password is None:
            return 1

        sudo_password = _prompt_sudo_password_if_needed(args)
        if getattr(args, "ask_sudo_password", False) and sudo_password is None:
            print("\nOperazione annullata.", file=sys.stderr)
            return 1

        n_coll = sum(1 for name, _ in _COLLECTOR_FACTORIES if _selected(name, tools))
        n_tools = sum(1 for name, _ in _TOOL_FACTORIES if _selected(name, tools))
        external_scan = bool(getattr(args, "external_scan", False))
        if external_scan and not valid_external_host(args.host):
            print(f"ERRORE: --external-scan richiede un singolo host valido, non '{args.host}'.",
                  file=sys.stderr)
            return 2
        total = 1 + 1 + n_coll + n_tools + (1 if external_scan else 0) + 1  # conn + sistema + coll + tools + [ext] + report
        progress = ProgressReporter(enabled=True, total_steps=total)
        progress.banner("")
        progress.banner(f"Assessment SSH: {args.user}@{args.host}:{args.port}")
        progress.banner(f"Tipo: {', '.join(requested)} ({total} step)")
        progress.banner("")

        try:
            a = _run_ssh_assessment(
                host=args.host,
                user=args.user,
                port=args.port,
                key=args.key,
                tools=tools,
                keep_tools=keep_tools,
                full_clamav_scan=full_clamav_scan,
                password=password,
                sudo_password=sudo_password,
                no_install=args.no_install,
                progress=progress,
                clamav_paths=clamav_paths,
                accept_new_host_key=args.accept_new_host_key,
                external_scan=external_scan,
                allow_epel=allow_epel,
            )
        except SSHConnectionError as e:
            progress.blank()
            _print_ssh_error(e)
            return 2
        except KeyboardInterrupt:
            progress.blank()
            progress.banner("\n  Interrotto dall'utente.")
            return 130
        # wipe password dalla memoria
        password = None
        sudo_password = None

        _apply_imports(a, imports)
        written = _write_reports(a, out_dir, formats, args.compare, not args.no_compare, layer,
                                 args.wazuh_log)
        render_console_summary(a, report_paths=written)
        return _fail_on_exit(args.fail_on, [a])

    if args.command == "fleet":
        if args.compare or imports:
            print("ERRORE: con 'fleet' --compare e --import-polyscan non sono ammessi: ogni host si "
                  "confronta da solo con la sua scansione precedente, e i rapporti polyscan riguardano "
                  "un'applicazione precisa (usali con 'ssh' sul suo server).", file=sys.stderr)
            return 1
        return _fleet_command(args, cfg, requested, extras, keep_tools, full_clamav_scan,
                              clamav_paths, formats, out_dir, allow_epel, layer)

    if args.command == "compare":
        return _compare_command(args.old, args.new)

    build_parser().print_help()
    return 0


def _fail_on_exit(threshold: str | None, assessments: list[Assessment]) -> int:
    """Codice di uscita per --fail-on: 4 se c'è almeno un finding di quella severità o più grave."""
    if not threshold:
        return 0
    limit = _SEV_RANK[threshold.lower()]
    for a in assessments:
        hit = [f for f in a.findings if _SEV_RANK.get(f.severity.value.lower(), 0) >= limit]
        if hit:
            print(f"\n  --fail-on {threshold}: {len(hit)} finding di severità {threshold.upper()} o superiore "
                  f"su {a.metadata.get('name') or a.target} (uscita {FAIL_ON_EXIT}).", file=sys.stderr)
            return FAIL_ON_EXIT
    return 0


def _fleet_command(args, cfg, requested, extras, keep_tools, full_clamav_scan,
                   clamav_paths, formats, out_dir, allow_epel, layer=None) -> int:
    return _fleet_run(args, cfg, requested, extras, keep_tools, full_clamav_scan,
                      clamav_paths, formats, out_dir, allow_epel, layer)[0]


def _fleet_run(args, cfg, requested, extras, keep_tools, full_clamav_scan,
               clamav_paths, formats, out_dir, allow_epel, layer=None) -> tuple[int, list[Path]]:
    """Assessment di tutti gli host dell'inventario. Restituisce (codice di uscita, riepiloghi scritti)."""
    try:
        hosts = load_inventory(args.inventory)
    except InventoryError as e:
        print(f"ERRORE: {e}", file=sys.stderr)
        return 1, []
    for h in hosts:
        bad = _unknown_tools(h.tools or [])
        if bad:
            print(f"ERRORE: {h.label}: controllo o tool sconosciuto: {', '.join(bad)}.", file=sys.stderr)
            return 1, []
        for var in (h.password_env, h.sudo_password_env):
            if var and var not in os.environ:
                print(f"ERRORE: {h.label}: variabile d'ambiente '{var}' non impostata.", file=sys.stderr)
                return 1, []
    if getattr(args, "ask_sudo_password", False):
        print("ERRORE: con più host usa sudo_password_env nell'inventario invece di --ask-sudo-password.",
              file=sys.stderr)
        return 1, []

    def run_one(h: FleetHost) -> HostResult:
        tools = _expand_tools(h.tools, cfg, extras) if h.tools else _expand_tools(requested, cfg, extras)
        a = _run_ssh_assessment(
            host=h.host, user=h.user, port=h.port, key=h.key, tools=tools,
            keep_tools=keep_tools, full_clamav_scan=full_clamav_scan,
            password=os.environ.get(h.password_env) if h.password_env else None,
            sudo_password=os.environ.get(h.sudo_password_env) if h.sudo_password_env else None,
            no_install=args.no_install, progress=None, clamav_paths=clamav_paths,
            accept_new_host_key=h.accept_new_host_key or args.accept_new_host_key,
            external_scan=h.external_scan and valid_external_host(h.host), allow_epel=allow_epel,
        )
        if h.name:
            a.metadata["name"] = h.name
        reports = _write_reports(a, out_dir, formats, args.compare, not args.no_compare, layer,
                                 args.wazuh_log)
        return HostResult(h, assessment=a, reports=reports)

    def on_done(r: HostResult, n: int, total: int) -> None:
        if r.ok:
            a = r.assessment
            print(f"  [{n}/{total}] {r.host.label}: {a.risk_level} {a.risk_score}/100 "
                  f"({len(a.findings)} finding, {r.seconds:.0f} s)", flush=True)
        else:
            print(f"  [{n}/{total}] {r.host.label}: NON RAGGIUNTO — {r.error}", flush=True)

    parallel = max(1, min(MAX_PARALLEL, args.parallel))
    print(f"\nAssessment di {len(hosts)} host ({min(parallel, len(hosts))} alla volta)…\n", flush=True)
    try:
        results = run_fleet(hosts, run_one, parallel, on_done)
    except KeyboardInterrupt:
        print("\n  Interrotto: attendo che gli host in corso finiscano la pulizia.", file=sys.stderr)
        return 130, []
    written = generate_fleet_reports(results, out_dir, formats)
    ok = sum(1 for r in results if r.ok)
    print(f"\n  Host analizzati: {ok} su {len(results)}")
    for p in written:
        print(f"  Riepilogo: {p}")
    print()
    code = 0 if ok == len(results) else 3
    if code == 0:
        code = _fail_on_exit(getattr(args, "fail_on", None), [r.assessment for r in results if r.ok])
    return code, written


def _compare_command(old_path: str, new_path: str) -> int:
    from risk_assessor.reports.console_report import render_comparison
    from risk_assessor.risk.compare import assessment_from_dict

    old, new = load_assessment(Path(old_path)), load_assessment(Path(new_path))
    for path, data in ((old_path, old), (new_path, new)):
        if data is None:
            print(f"ERRORE: '{path}' non è un assessment.json leggibile.", file=sys.stderr)
            return 1
    current = assessment_from_dict(new)
    cmp = compare(current, old)
    print(f"\n  {current.target}: {cmp.previous_date} → {current.started_at.strftime('%d/%m/%Y %H:%M UTC')}")
    if cmp.previous_target != current.target:
        print(f"  ATTENZIONE: target diversi ({cmp.previous_target} e {current.target}).")
    print()
    render_comparison(cmp.to_dict())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
