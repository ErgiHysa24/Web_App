"""Configuration loader.

Carica config.yaml dalla root del progetto. Se il file manca,
ritorna una configurazione di default. I valori CLI hanno precedenza.
"""
from __future__ import annotations
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml


DEFAULT_CONFIG_PATH = Path("config.yaml")

# Tool che la scansione completa (--all) NON include se non vengono abilitati
# esplicitamente nel config, aggiunti con --with o dal menu "Strumenti opzionali",
# o richiesti con --tools:
# - trivy: scarica un binario e un database da internet;
# - aide: la prima esecuzione crea solo la baseline (molto lenta) e non dà risultati;
# - rkhunter: non più mantenuto (ultima versione nel 2018), il più lento (minuti) e con
#   molti falsi positivi; per i rootkit c'è chkrootkit.
OPT_IN_TOOLS = frozenset({"trivy", "aide", "rkhunter"})


@dataclass
class ToolConfig:
    enabled: bool = True
    full_scan: bool = False
    scan_paths: list[str] = field(default_factory=lambda: ["/etc", "/tmp", "/var/tmp"])


@dataclass
class CleanupConfig:
    enabled: bool = True


@dataclass
class InstallConfig:
    # RHEL, Rocky, Alma...: Lynis, rkhunter e ClamAV stanno nel repository EPEL. Attivarlo
    # aggiunge un repository al server, quindi solo se richiesto (viene tolto a fine scansione).
    epel: bool = False


@dataclass
class ReportConfig:
    formats: list[str] = field(default_factory=lambda: ["json", "md", "html"])
    output_dir: str = "reports"


@dataclass
class Config:
    tools: dict[str, ToolConfig] = field(default_factory=dict)
    cleanup: CleanupConfig = field(default_factory=CleanupConfig)
    install: InstallConfig = field(default_factory=InstallConfig)
    report: ReportConfig = field(default_factory=ReportConfig)

    def enabled_tools(self) -> list[str]:
        """Ritorna la lista dei nomi dei tool abilitati."""
        return [name for name, cfg in self.tools.items() if cfg.enabled]

    def tool_cfg(self, name: str) -> ToolConfig:
        return self.tools.get(name, ToolConfig(enabled=name not in OPT_IN_TOOLS))


KNOWN_SECTIONS = frozenset({"tools", "cleanup", "install", "report"})


def load_config(path: Path | str | None = None) -> Config:
    """Carica la configurazione. Se il file manca o è invalido, ritorna il default."""
    path = Path(path) if path else DEFAULT_CONFIG_PATH
    if not path.exists():
        return _default_config()

    try:
        with path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
    except (yaml.YAMLError, OSError) as e:
        print(f"ATTENZIONE: {path} non è leggibile ({type(e).__name__}): si usano le impostazioni "
              "predefinite.", file=sys.stderr)
        return _default_config()
    if not isinstance(raw, dict):
        print(f"ATTENZIONE: {path} non contiene un elenco di impostazioni: si usano le predefinite.",
              file=sys.stderr)
        return _default_config()
    unknown = sorted(set(raw) - KNOWN_SECTIONS)
    if unknown:
        print(f"ATTENZIONE: {path}: sezioni sconosciute ignorate: {', '.join(unknown)} "
              f"(ammesse: {', '.join(sorted(KNOWN_SECTIONS))}).", file=sys.stderr)
    return _parse(raw)


def _parse(raw: dict) -> Config:
    cfg = Config()

    tools_raw = raw.get("tools") or {}
    if isinstance(tools_raw, dict):
        for name, entry in tools_raw.items():
            if isinstance(entry, dict):
                tcfg = ToolConfig(
                    enabled=bool(entry.get("enabled", True)),
                    full_scan=bool(entry.get("full_scan", False)),
                    scan_paths=list(entry.get("scan_paths") or ["/etc", "/tmp", "/var/tmp"]),
                )
            else:
                # entry può essere solo True/False
                tcfg = ToolConfig(enabled=bool(entry))
            cfg.tools[name] = tcfg

    if not cfg.tools:
        cfg.tools = _default_tools()

    cleanup_raw = raw.get("cleanup") or {}
    if isinstance(cleanup_raw, dict):
        cfg.cleanup = CleanupConfig(enabled=bool(cleanup_raw.get("enabled", True)))

    install_raw = raw.get("install") or {}
    if isinstance(install_raw, dict):
        cfg.install = InstallConfig(epel=bool(install_raw.get("epel", False)))

    report_raw = raw.get("report") or {}
    if isinstance(report_raw, dict):
        formats = report_raw.get("formats")
        cfg.report = ReportConfig(
            formats=list(formats) if formats else ["json", "md", "html"],
            output_dir=str(report_raw.get("output_dir") or "reports"),
        )


    return cfg


def _default_tools() -> dict[str, ToolConfig]:
    names = [
        "linux", "users", "ssh_config", "firewall", "services", "filesystem", "packages",
        "auth_policy", "kernel", "logging", "updates", "persistence", "protections",
        "nmap", "lynis", "rkhunter", "chkrootkit", "openscap", "clamav",
        "aide", "debsecan", "debsums", "trivy",
    ]
    return {n: ToolConfig(enabled=n not in OPT_IN_TOOLS) for n in names}


def _default_config() -> Config:
    return Config(tools=_default_tools())
