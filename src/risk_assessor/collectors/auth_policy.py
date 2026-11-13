"""Politica delle password e dei privilegi: login.defs, qualità password, blocco account, sudoers.

Solo lettura. I file privilegiati (sudoers) si leggono con `sudo -n` solo se serve; se non è
possibile il controllo lo dichiara invece di far credere che vada tutto bene.
"""
from __future__ import annotations

import re

from risk_assessor.collectors._platform import install_hint, package_name
from risk_assessor.collectors._privileged import run_privileged
from risk_assessor.host import host_info
from risk_assessor.executor import BaseExecutor
from risk_assessor.models import Confidence, Finding, Severity


def _f(title, sev, desc, evidence, reco, source, conf=Confidence.HIGH, command=""):
    return Finding(title=title, category="authentication", severity=sev, description=desc,
                   evidence=evidence, recommendation=reco, source=source,
                   confidence=conf, command=command)


def parse_login_defs(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            out[parts[0].upper()] = parts[1].strip()
    return out


_NOPASSWD = re.compile(r"^\s*(?P<who>[^\s#=]+)\s+[^=\s]+\s*=\s*(?:\([^)]*\)\s*)?(?P<rest>.*NOPASSWD.*)$")


def parse_sudoers(text: str) -> tuple[list[tuple[str, str]], bool]:
    """Ritorna ([(chi, regola)] con NOPASSWD, presenza di `!authenticate`)."""
    rules: list[tuple[str, str]] = []
    no_auth = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("@"):
            continue
        if line.startswith("Defaults"):
            if "!authenticate" in line.replace(" ", ""):
                no_auth = True
            continue
        m = _NOPASSWD.match(line)
        if m:
            rules.append((m.group("who"), line))
    return rules, no_auth


class AuthPolicyCollector:
    name = "auth_policy"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._login_defs(executor))
        findings.extend(self._pam(executor))
        findings.extend(self._sudoers(executor))
        return findings

    # ---------------------------------------------------------------- login.defs
    def _login_defs(self, executor) -> list[Finding]:
        out, _, rc = executor.execute_command(["cat", "/etc/login.defs"])
        if rc != 0 or not out.strip():
            return []
        d = parse_login_defs(out)
        res: list[Finding] = []
        try:
            max_days = int(d.get("PASS_MAX_DAYS", ""))
        except ValueError:
            max_days = None
        if max_days is not None and (max_days > 365 or max_days < 0):
            res.append(_f(
                "Le password non hanno una scadenza ragionevole", Severity.LOW,
                f"PASS_MAX_DAYS vale {max_days}: le password nuove non scadono praticamente mai. "
                "Le linee guida CIS indicano al massimo 365 giorni.",
                f"PASS_MAX_DAYS {max_days}",
                "Impostare PASS_MAX_DAYS 365 (o secondo la politica aziendale). "
                "Vale per gli account creati dopo la modifica.",
                "auth-policy:pass-max-days", Confidence.MEDIUM))
        method = d.get("ENCRYPT_METHOD", "").upper()
        if method in ("MD5", "DES"):
            res.append(_f(
                f"Hash delle password debole ({method})", Severity.HIGH,
                "Le nuove password vengono salvate con un algoritmo facile da attaccare.",
                f"ENCRYPT_METHOD {method}",
                "Usare ENCRYPT_METHOD YESCRYPT o SHA512.",
                "auth-policy:encrypt-method"))
        return res

    # ----------------------------------------------------------------------- PAM
    def _pam(self, executor) -> list[Finding]:
        res: list[Finding] = []
        out, _, rc = executor.execute_command(["grep", "-rEs", "pam_pwquality|pam_cracklib|pam_passwdqc", "/etc/pam.d"])
        have_quality = rc == 0 and bool(out.strip())
        pam_present, _, prc = executor.execute_command(["test", "-d", "/etc/pam.d"])
        if prc != 0:
            return []  # niente PAM (container minimale): non si può dire nulla
        host = host_info(executor)
        if not have_quality:
            pkg = package_name(host, "pwquality")
            res.append(_f(
                "Nessun controllo sulla qualità delle password", Severity.MEDIUM,
                "PAM non usa pam_pwquality, pam_cracklib o pam_passwdqc: sono ammesse password banali.",
                "nessun riferimento in /etc/pam.d", f"Installare e configurare {pkg} "
                "(minlen almeno 12).", "auth-policy:no-pwquality", Confidence.MEDIUM,
                command=install_hint(host, "pwquality")))
        else:
            conf, _, crc = executor.execute_command(["cat", "/etc/security/pwquality.conf"])
            if crc == 0:
                m = re.search(r"^\s*minlen\s*=\s*(\d+)", conf, re.MULTILINE)
                if m and int(m.group(1)) < 8:
                    res.append(_f(
                        f"Lunghezza minima delle password troppo bassa ({m.group(1)})", Severity.MEDIUM,
                        "pwquality accetta password molto corte.", f"minlen = {m.group(1)}",
                        "Impostare minlen almeno a 12.", "auth-policy:minlen"))

        lock, _, lrc = executor.execute_command(["grep", "-rEs", "pam_faillock|pam_tally2|pam_tally", "/etc/pam.d"])
        if not (lrc == 0 and lock.strip()):
            res.append(_f(
                "Nessun blocco dopo tentativi di accesso falliti", Severity.MEDIUM,
                "PAM non usa pam_faillock né pam_tally2: i tentativi di indovinare le password non vengono "
                "limitati a livello di account (un fail2ban può compensare per SSH).",
                "nessun riferimento in /etc/pam.d",
                "Configurare pam_faillock (deny=5, unlock_time=900) o usare fail2ban.",
                "auth-policy:no-lockout", Confidence.MEDIUM,
                # Su Fedora e RHEL authselect lo attiva con un comando (sugli altri va
                # modificata la configurazione PAM a mano).
                command="sudo authselect enable-feature with-faillock"
                if host.family in ("fedora", "rhel") else ""))
        return res

    # ------------------------------------------------------------------- sudoers
    def _sudoers(self, executor) -> list[Finding]:
        texts: list[str] = []
        main = run_privileged(executor, ["cat", "/etc/sudoers"])
        if main.status == "absent":
            return []  # sudo non installato
        if main.inconclusive:
            return [_f(
                "Configurazione di sudo non verificabile", Severity.INFO,
                "/etc/sudoers non è leggibile senza privilegi: le regole NOPASSWD non sono state controllate.",
                (main.err or main.out).strip()[:200],
                "Rieseguire con un utente che possa leggere sudoers (sudo senza password).",
                "auth-policy:sudoers-unreadable", Confidence.LOW)]
        texts.append(main.out)
        lst = run_privileged(executor, ["find", "/etc/sudoers.d", "-maxdepth", "1", "-type", "f"])
        if lst.ok:
            for path in lst.out.split()[:30]:
                if re.fullmatch(r"/etc/sudoers\.d/[A-Za-z0-9._-]+", path):
                    r = run_privileged(executor, ["cat", path])
                    if r.ok:
                        texts.append(r.out)

        rules: list[tuple[str, str]] = []
        no_auth = False
        for t in texts:
            r, na = parse_sudoers(t)
            rules.extend(r)
            no_auth = no_auth or na

        res: list[Finding] = []
        broad = [(w, line) for w, line in rules if w != "root" and re.search(r"NOPASSWD:\s*ALL\b", line)]
        if broad:
            who = ", ".join(sorted({w for w, _ in broad}))
            res.append(_f(
                f"sudo senza password per qualsiasi comando: {who}"[:120], Severity.MEDIUM,
                "Questi utenti o gruppi diventano root senza password: chi ne ottiene l'accesso ottiene root.",
                "\n".join(line for _, line in broad)[:500],
                "Limitare NOPASSWD ai soli comandi necessari, oppure richiedere la password.",
                "auth-policy:sudo-nopasswd-all"))
        narrow = [(w, line) for w, line in rules if (w, line) not in broad and w != "root"]
        if narrow:
            res.append(_f(
                f"sudo senza password per alcuni comandi ({len(narrow)} regole)", Severity.INFO,
                "Sono presenti regole NOPASSWD limitate a comandi specifici: verificare che siano necessarie.",
                "\n".join(line for _, line in narrow)[:500],
                "Controllare che i comandi consentiti non permettano di ottenere una shell root.",
                "auth-policy:sudo-nopasswd-cmds", Confidence.MEDIUM))
        if no_auth:
            res.append(_f(
                "sudo configurato senza autenticazione (!authenticate)", Severity.HIGH,
                "Defaults !authenticate disattiva la richiesta di password per sudo.",
                "Defaults !authenticate", "Rimuovere !authenticate da sudoers.",
                "auth-policy:sudo-no-authenticate"))
        return res
