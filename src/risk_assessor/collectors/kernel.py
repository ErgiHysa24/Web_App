"""Hardening del kernel e della rete tramite i parametri sysctl (sola lettura).

Si segnalano solo le deviazioni dalle impostazioni consigliate (linee guida CIS/KSPP).
Un parametro che non esiste (kernel o container diversi) viene saltato in silenzio.
"""
from __future__ import annotations

from dataclasses import dataclass

from risk_assessor.collectors._platform import unverifiable
from risk_assessor.executor import BaseExecutor
from risk_assessor.host import host_info
from risk_assessor.models import Confidence, Finding, Severity


@dataclass(frozen=True)
class _Rule:
    key: str
    bad: tuple[str, ...] | None      # valori problematici (None: tutto tranne `good`)
    good: str | None
    severity: Severity
    title: str
    description: str
    category: str = "kernel"
    confidence: Confidence = Confidence.MEDIUM


_RULES = (
    _Rule("kernel.randomize_va_space", None, "2", Severity.MEDIUM, "ASLR non completo",
          "La randomizzazione dello spazio di indirizzi non è al massimo: gli exploit sono più affidabili."),
    _Rule("kernel.kptr_restrict", ("0",), "1", Severity.MEDIUM, "Indirizzi del kernel esposti agli utenti",
          "kptr_restrict=0 permette di leggere gli indirizzi del kernel, utili per sfruttare vulnerabilità."),
    _Rule("kernel.dmesg_restrict", ("0",), "1", Severity.LOW, "dmesg leggibile da tutti gli utenti",
          "Gli utenti non privilegiati possono leggere i messaggi del kernel."),
    _Rule("kernel.yama.ptrace_scope", ("0",), "1", Severity.LOW, "ptrace senza restrizioni",
          "Un processo può ispezionare e manipolare gli altri dello stesso utente."),
    _Rule("kernel.unprivileged_bpf_disabled", ("0",), "1", Severity.LOW, "BPF consentito agli utenti non privilegiati",
          "Superficie d'attacco aggiuntiva nel kernel."),
    _Rule("fs.protected_hardlinks", ("0",), "1", Severity.MEDIUM, "Hard link non protetti",
          "Senza protezione si possono creare hard link a file altrui per attacchi di escalation."),
    _Rule("fs.protected_symlinks", ("0",), "1", Severity.MEDIUM, "Link simbolici non protetti",
          "Senza protezione sono possibili attacchi con link simbolici in cartelle condivise (/tmp).",),
    _Rule("fs.suid_dumpable", None, "0", Severity.MEDIUM, "Core dump dei programmi SUID consentiti",
          "I core dump di programmi con privilegi possono contenere dati sensibili."),
    _Rule("net.ipv4.tcp_syncookies", ("0",), "1", Severity.MEDIUM, "SYN cookie disattivati",
          "Il sistema è più vulnerabile agli attacchi di tipo SYN flood.", "network"),
    _Rule("net.ipv4.conf.all.accept_redirects", ("1",), "0", Severity.MEDIUM, "Accetta i reindirizzamenti ICMP",
          "Un attaccante sulla rete può alterare le rotte del sistema.", "network"),
    _Rule("net.ipv4.conf.all.accept_source_route", ("1",), "0", Severity.MEDIUM, "Accetta il routing dalla sorgente",
          "Permette ai pacchetti di imporre il percorso, aggirando filtri.", "network"),
    _Rule("net.ipv4.conf.all.send_redirects", ("1",), "0", Severity.LOW, "Invia reindirizzamenti ICMP",
          "Una macchina che non fa da router non dovrebbe inviarli.", "network"),
    _Rule("net.ipv4.conf.all.rp_filter", ("0",), "1", Severity.LOW, "Controllo dell'indirizzo sorgente disattivato",
          "Il filtro rp_filter riduce lo spoofing degli indirizzi IP.", "network"),
    _Rule("net.ipv4.icmp_echo_ignore_broadcasts", ("0",), "1", Severity.LOW, "Risponde ai ping in broadcast",
          "Può essere usato per attacchi di amplificazione (smurf).", "network"),
    _Rule("net.ipv6.conf.all.accept_redirects", ("1",), "0", Severity.LOW, "Accetta i reindirizzamenti ICMPv6",
          "Un attaccante sulla rete può alterare le rotte IPv6.", "network"),
    _Rule("net.ipv4.ip_forward", ("1",), "0", Severity.LOW, "Inoltro IP attivo",
          "Giusto solo se la macchina fa da router o ospita container/VPN; altrimenti va disattivato.",
          "network", Confidence.LOW),
)


def _command(key: str, good: str) -> str:
    return (f"echo '{key} = {good}' | sudo tee -a /etc/sysctl.d/99-watchdog-hardening.conf"
            " && sudo sysctl -p /etc/sysctl.d/99-watchdog-hardening.conf")


# Legge tutti i parametri in un solo comando, direttamente da /proc/sys: non serve il
# programma sysctl (assente nelle installazioni minime o fuori dal PATH dell'utente)
# e via SSH è un solo round-trip invece di uno per parametro.
_READ_SCRIPT = 'for f in "$@"; do if [ -r "$f" ]; then printf "%s=" "$f"; cat "$f"; fi; done'
# Stato di Secure Boot dalla variabile EFI (l'ultimo byte: 1 attivo, 0 no), se mokutil manca.
_SECURE_BOOT_VAR = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"


def _proc_path(key: str) -> str:
    return "/proc/sys/" + key.replace(".", "/")


def read_sysctl(executor: BaseExecutor, keys: list[str]) -> dict[str, str]:
    """{chiave: valore} per i parametri leggibili; quelli assenti mancano dal risultato."""
    paths = {_proc_path(k): k for k in keys}
    out, _, _ = executor.execute_command(["sh", "-c", _READ_SCRIPT, "sh", *paths])
    values: dict[str, str] = {}
    for line in (out or "").splitlines():
        path, sep, value = line.partition("=")
        if sep and path in paths and value.strip():
            values[paths[path]] = value.strip().split()[0]
    return values


class KernelCollector:
    name = "kernel"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        findings: list[Finding] = []
        host = host_info(executor)
        rules = _RULES
        if host.container:
            # In un container i parametri net.* sono del suo namespace di rete; gli altri
            # (kptr_restrict, protected_symlinks, ...) sono del kernel dell'host e da qui non
            # si cambiano: si dice, invece di consigliare un /etc/sysctl.d/ che non avrebbe effetto.
            rules = [r for r in _RULES if r.key.startswith("net.")]
            findings.append(unverifiable(
                "Parametri del kernel dell'host non valutabili dal container",
                f"Il sistema è un container ({host.container}): i parametri sysctl non di rete appartengono "
                "al kernel dell'host e vanno controllati lì.",
                ", ".join(r.key for r in _RULES if not r.key.startswith("net.")),
                "kernel:container", "kernel"))
        values = read_sysctl(executor, [rule.key for rule in rules])
        for rule in rules:
            value = values.get(rule.key)
            if value is None:
                continue
            is_bad = (value in rule.bad) if rule.bad is not None else (value != rule.good)
            if not is_bad:
                continue
            findings.append(Finding(
                title=f"{rule.title} ({rule.key}={value})",
                category=rule.category, severity=rule.severity,
                description=rule.description,
                evidence=f"{rule.key} = {value} (consigliato: {rule.good})",
                recommendation=f"Impostare {rule.key} = {rule.good} in /etc/sysctl.d/.",
                source=f"kernel:{rule.key}", confidence=rule.confidence,
                command=_command(rule.key, rule.good or ""),
            ))
        if not values:
            return findings  # nessun parametro leggibile (ambiente ristretto): niente da dire

        state = self._secure_boot(executor)
        if state is False:
            findings.append(Finding(
                title="Secure Boot disattivato", category="kernel", severity=Severity.INFO,
                description="L'avvio sicuro non è attivo: il caricamento di bootloader o moduli non firmati non è bloccato.",
                evidence="mokutil --sb-state / variabile EFI SecureBoot: disattivato",
                recommendation="Attivare Secure Boot dal firmware, se l'hardware e la distribuzione lo supportano.",
                source="kernel:secure-boot", confidence=Confidence.MEDIUM,
            ))
        return findings

    @staticmethod
    def _secure_boot(executor: BaseExecutor) -> bool | None:
        """True/False se si riesce a saperlo, None altrimenti (BIOS, container, permessi)."""
        out, _, rc = executor.execute_command(["mokutil", "--sb-state"])
        if rc == 0 and "secureboot" in out.lower().replace(" ", ""):
            return "enabled" in out.lower()
        out, _, rc = executor.execute_command(
            ["sh", "-c", 'f="$1"; [ -r "$f" ] && od -An -t u1 "$f"', "sh", _SECURE_BOOT_VAR])
        numbers = (out or "").split()
        if rc == 0 and numbers and numbers[-1] in ("0", "1"):
            return numbers[-1] == "1"
        return None
