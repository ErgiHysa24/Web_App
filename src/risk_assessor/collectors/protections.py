"""Protezioni del sistema su Linux (sola lettura).

- Controllo di accesso obbligatorio (MAC): SELinux (RHEL, Fedora...) o AppArmor (Debian,
  Ubuntu, SUSE...). Limita i danni di un servizio compromesso anche se gira come root.
- Cifratura del disco di sistema (LUKS/dm-crypt): protegge i dati se il disco viene rubato.

Dentro un container lo stato dipende dall'host e non si può valutare: il report lo dice.
"""
from __future__ import annotations

from risk_assessor.collectors._platform import install_hint, unverifiable
from risk_assessor.collectors._privileged import run_privileged
from risk_assessor.executor import BaseExecutor
from risk_assessor.host import HostInfo, host_info
from risk_assessor.models import Confidence, Finding, Severity

# Tutto ciò che serve in un solo comando di sola lettura (nessun dato esterno nello script).
_STATE_SCRIPT = r"""
[ -d /sys/fs/selinux ] && echo "selinux_fs=1"
[ -r /sys/fs/selinux/enforce ] && echo "selinux_enforce=$(cat /sys/fs/selinux/enforce)"
[ -r /etc/selinux/config ] && grep -E '^[[:space:]]*SELINUX=' /etc/selinux/config | head -1 | sed 's/^[[:space:]]*/selinux_config_line=/'
[ -r /sys/module/apparmor/parameters/enabled ] && echo "apparmor_enabled=$(cat /sys/module/apparmor/parameters/enabled)"
echo "done=1"
"""

# Famiglie in cui ci si aspetta l'uno o l'altro (consiglio da dare se manca tutto).
_EXPECTED = {"fedora": "SELinux", "rhel": "SELinux", "debian": "AppArmor", "suse": "AppArmor",
             "arch": "AppArmor", "alpine": "AppArmor"}


def _f(title, sev, desc, evidence, reco, source, conf=Confidence.MEDIUM, command=""):
    return Finding(title=title, category="protections", severity=sev, description=desc,
                   evidence=evidence, recommendation=reco, source=source,
                   confidence=conf, command=command)


def parse_state(text: str) -> dict[str, str]:
    state: dict[str, str] = {}
    for line in (text or "").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            state[key.strip()] = value.strip()
    return state


class ProtectionsCollector:
    name = "protections"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        host = host_info(executor)
        if host.container:
            return [unverifiable(
                "Protezioni del sistema non valutabili in un container",
                "SELinux, AppArmor e cifratura del disco appartengono all'host che esegue il "
                "container: vanno controllati lì.",
                f"container {host.container}", "protections:container", "protections")]
        out, _, _ = executor.execute_command(["sh", "-c", _STATE_SCRIPT])
        state = parse_state(out)
        if state.get("done") != "1":
            return []
        findings = self._mac(executor, host, state)
        findings.extend(self._encryption(executor))
        return findings

    # ------------------------------------------------------------------ SELinux / AppArmor
    def _mac(self, executor, host: HostInfo, state: dict[str, str]) -> list[Finding]:
        if state.get("selinux_fs") == "1":
            return self._selinux(state)
        if state.get("apparmor_enabled", "").upper().startswith("Y"):
            return self._apparmor(executor, host)
        config = state.get("selinux_config_line", "").split("=", 1)[-1].strip().lower()
        expected = _EXPECTED.get(host.family, "SELinux o AppArmor")
        evidence = "SELinux non caricato" + (f" (config: SELINUX={config})" if config else "") + \
                   ", AppArmor non attivo"
        hint = install_hint(host, "apparmor") if expected == "AppArmor" else ""
        return [_f(
            "Nessun controllo di accesso obbligatorio attivo (SELinux/AppArmor)", Severity.MEDIUM,
            "Senza SELinux o AppArmor un servizio compromesso può fare tutto ciò che il suo utente può "
            "fare: nessun confine aggiuntivo limita i danni.",
            evidence,
            f"Attivare {expected} (in modalità enforcing/enforce) con i profili della distribuzione.",
            "protections:no-mac", command=hint)]

    @staticmethod
    def _selinux(state: dict[str, str]) -> list[Finding]:
        enforce = state.get("selinux_enforce")
        if enforce == "1":
            return [_f("SELinux attivo (enforcing)", Severity.INFO,
                       "SELinux applica le sue regole: un servizio compromesso resta confinato.",
                       "/sys/fs/selinux/enforce = 1", "Nessuna azione richiesta.",
                       "protections:selinux-enforcing", Confidence.HIGH)]
        return [_f(
            "SELinux in modalità permissive", Severity.MEDIUM,
            "SELinux registra le violazioni ma non le blocca: la protezione è di fatto spenta.",
            f"/sys/fs/selinux/enforce = {enforce or '?'}",
            "Correggere le violazioni registrate (ausearch -m avc) e passare a enforcing "
            "(SELINUX=enforcing in /etc/selinux/config).",
            "protections:selinux-permissive", Confidence.HIGH,
            command="sudo setenforce 1 && sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config")]

    @staticmethod
    def _apparmor(executor, host: HostInfo) -> list[Finding]:
        res = run_privileged(executor, ["cat", "/sys/kernel/security/apparmor/profiles"])
        if not res.ok:
            return [_f("AppArmor attivo", Severity.INFO,
                       "AppArmor è caricato; l'elenco dei profili richiede privilegi di root.",
                       "/sys/module/apparmor/parameters/enabled = Y", "Nessuna azione richiesta.",
                       "protections:apparmor-enabled", Confidence.MEDIUM)]
        lines = [ln for ln in res.out.splitlines() if ln.strip()]
        enforce = sum(1 for ln in lines if ln.rstrip().endswith("(enforce)"))
        complain = sum(1 for ln in lines if ln.rstrip().endswith("(complain)"))
        if enforce == 0:
            return [_f(
                "AppArmor attivo ma senza profili applicati", Severity.LOW,
                "AppArmor è caricato ma nessun profilo è in modalità enforce: non limita alcun programma.",
                f"profili: {enforce} enforce, {complain} complain",
                "Installare i profili della distribuzione (apparmor-profiles) e metterli in enforce.",
                "protections:apparmor-no-profiles", Confidence.HIGH,
                command=install_hint(host, "apparmor-profiles"))]
        return [_f("AppArmor attivo", Severity.INFO,
                   f"AppArmor applica {enforce} profili ({complain} solo in osservazione).",
                   f"profili: {enforce} enforce, {complain} complain", "Nessuna azione richiesta.",
                   "protections:apparmor-enabled", Confidence.HIGH)]

    # ---------------------------------------------------------------- cifratura disco
    @staticmethod
    def _encryption(executor) -> list[Finding]:
        """Il file system di / sta su un dispositivo cifrato (LUKS/dm-crypt)?"""
        src, _, rc = executor.execute_command(["findmnt", "-n", "-o", "SOURCE", "/"])
        source = src.strip().split("[")[0]
        if rc != 0 or not source.startswith("/dev/"):
            return []          # niente findmnt, overlay, tmpfs, ZFS...: non si può dire
        chain, _, rc = executor.execute_command(["lsblk", "-n", "-s", "-r", "-o", "TYPE", source])
        if rc != 0 or not chain.strip():
            return []
        types = chain.split()
        if "crypt" in types:
            return [_f("Disco di sistema cifrato", Severity.INFO,
                       "Il file system principale sta su un volume cifrato (LUKS).",
                       f"/ su {source}: {' > '.join(types)}", "Nessuna azione richiesta.",
                       "protections:disk-encrypted", Confidence.HIGH)]
        return [_f(
            "Disco di sistema non cifrato", Severity.LOW,
            "Chi ottiene fisicamente il disco (furto, smaltimento, snapshot di una VM) può leggerne tutti "
            "i dati. Per un server in un datacenter controllato il rischio è minore che per un portatile.",
            f"/ su {source}: {' > '.join(types)}",
            "Valutare la cifratura LUKS del disco (all'installazione o con una migrazione pianificata).",
            "protections:disk-not-encrypted", Confidence.MEDIUM)]
