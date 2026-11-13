"""SSH configuration collector."""
from __future__ import annotations
from risk_assessor.collectors._privileged import run_privileged
from risk_assessor.executor import BaseExecutor
from risk_assessor.models import Finding, Severity, Confidence


def _sshd_fix(key: str, value: str) -> str:
    """Comando per correggere una direttiva già presente in sshd_config (con controllo prima del reload)."""
    return (
        f"sudo sed -i -E 's/^[[:space:]]*#?[[:space:]]*{key}[[:space:]].*/{key} {value}/' /etc/ssh/sshd_config"
        " && sudo sshd -t && (sudo systemctl reload ssh || sudo systemctl reload sshd)"
        f" && sudo sshd -T | grep -i {key}"
    )


class SSHConfigCollector:
    name = "ssh_config"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        content = self._read(executor, ["cat", "/etc/ssh/sshd_config"])
        if not content:
            return []
        cfg = self._parse(content)
        findings: list[Finding] = []
        findings.extend(self._check_permit_root_login(cfg))
        findings.extend(self._check_password_auth(cfg))
        findings.extend(self._check_empty_passwords(cfg))
        findings.extend(self._check_x11(cfg))
        findings.extend(self._check_protocol(cfg))
        findings.extend(self._check_port(cfg))
        findings.extend(self._check_effective(executor))
        return findings

    def _check_effective(self, executor: BaseExecutor) -> list[Finding]:
        res = run_privileged(executor, ["sshd", "-T"])
        if res.status == "absent":
            res = run_privileged(executor, ["/usr/sbin/sshd", "-T"])
        if res.ok and res.out.strip():
            return _effective_checks(_parse_effective(res.out))
        if res.inconclusive:
            return [_f(
                "SSH: configurazione effettiva non verificabile", Severity.INFO,
                "Per leggere la configurazione effettiva (`sshd -T`) servono i privilegi di root: "
                "i controlli su cifrari, MAC e limiti non sono stati eseguiti.",
                (res.err or res.out).strip()[:300],
                "Rieseguire con un utente che abbia sudo senza password per questa lettura.",
                "ssh-config:effective-unavailable", Confidence.LOW)]
        return []

    @staticmethod
    def _read(executor, cmd) -> str:
        out, err, rc = executor.execute_command(cmd)
        return out if rc == 0 else ""

    @staticmethod
    def _parse(content: str) -> dict[str, str]:
        cfg: dict[str, str] = {}
        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line and " " not in line.split("=", 1)[0]:
                key, _, value = line.partition("=")
            else:
                parts = line.split(None, 1)
                if len(parts) != 2:
                    continue
                key, value = parts
            cfg[key.strip().lower()] = value.strip()
        return cfg

    def _check_permit_root_login(self, cfg: dict[str, str]) -> list[Finding]:
        if "permitrootlogin" not in cfg:
            return [Finding(
                title="PermitRootLogin non configurato",
                category="authentication",
                severity=Severity.INFO,
                description="PermitRootLogin non esplicito; default OpenSSH è prohibit-password.",
                evidence="Setting mancante: PermitRootLogin",
                recommendation="Impostare esplicitamente PermitRootLogin no",
                source="ssh-config:permit-root-login",
                confidence=Confidence.MEDIUM,
            )]
        value = cfg["permitrootlogin"].lower()
        if value in ("yes", "prohibit-password"):
            return [Finding(
                title="PermitRootLogin abilitato",
                category="authentication",
                severity=Severity.HIGH,
                description=f"root può fare login SSH (PermitRootLogin={value}).",
                evidence=f"PermitRootLogin {value}",
                recommendation="Impostare PermitRootLogin no",
                command=_sshd_fix("PermitRootLogin", "no"),
                source="ssh-config:permit-root-login",
                confidence=Confidence.HIGH,
            )]
        return []

    def _check_password_auth(self, cfg: dict[str, str]) -> list[Finding]:
        if cfg.get("passwordauthentication", "").lower() == "yes":
            return [Finding(
                title="PasswordAuthentication abilitato",
                category="authentication",
                severity=Severity.HIGH,
                description="Autenticazione via password abilitata.",
                evidence="PasswordAuthentication yes",
                recommendation="Usare solo autenticazione con chiave pubblica",
                command=_sshd_fix("PasswordAuthentication", "no"),
                source="ssh-config:password-authentication",
                confidence=Confidence.HIGH,
            )]
        return []

    def _check_empty_passwords(self, cfg: dict[str, str]) -> list[Finding]:
        if cfg.get("permitemptypasswords", "").lower() == "yes":
            return [Finding(
                title="PermitEmptyPasswords abilitato",
                category="authentication",
                severity=Severity.CRITICAL,
                description="Account senza password possono fare login SSH.",
                evidence="PermitEmptyPasswords yes",
                recommendation="Impostare PermitEmptyPasswords no",
                command=_sshd_fix("PermitEmptyPasswords", "no"),
                source="ssh-config:empty-passwords",
                confidence=Confidence.HIGH,
            )]
        return []

    def _check_x11(self, cfg: dict[str, str]) -> list[Finding]:
        if cfg.get("x11forwarding", "").lower() == "yes":
            return [Finding(
                title="X11Forwarding abilitato",
                category="network",
                severity=Severity.LOW,
                description="X11 forwarding abilitato (superficie d'attacco aggiuntiva).",
                evidence="X11Forwarding yes",
                recommendation="Disabilitare X11Forwarding se non necessario",
                command=_sshd_fix("X11Forwarding", "no"),
                source="ssh-config:x11-forwarding",
                confidence=Confidence.MEDIUM,
            )]
        return []

    def _check_protocol(self, cfg: dict[str, str]) -> list[Finding]:
        value = cfg.get("protocol", "").lower()
        if "1" in value:
            return [Finding(
                title="SSH Protocol 1 abilitato",
                category="authentication",
                severity=Severity.CRITICAL,
                description="Protocollo SSHv1 è deprecato e insicuro.",
                evidence=f"Protocol {value}",
                recommendation="Usare solo Protocol 2",
                source="ssh-config:protocol-1",
                confidence=Confidence.HIGH,
            )]
        return []

    def _check_port(self, cfg: dict[str, str]) -> list[Finding]:
        value = cfg.get("port", "").strip()
        if value and value != "22":
            return [Finding(
                title=f"SSH su porta non standard: {value}",
                category="network",
                severity=Severity.INFO,
                description="SSH in ascolto su porta non standard.",
                evidence=f"Port {value}",
                recommendation="Assicurarsi che la porta sia filtrata dal firewall",
                source="ssh-config:port",
                confidence=Confidence.LOW,
            )]
        return []


# ---------------------------------------------------------------------------
# Hardening avanzato: usa la configurazione EFFETTIVA (`sshd -T`), cioè con i valori
# predefiniti e i file inclusi, non solo le righe scritte in sshd_config.
# ---------------------------------------------------------------------------

_WEAK_CIPHER_MARKERS = ("3des", "-cbc", "arcfour", "blowfish", "cast128", "rijndael-cbc")
_WEAK_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
             "diffie-hellman-group-exchange-sha1"}


def _parse_effective(text: str) -> dict[str, str]:
    cfg: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            cfg.setdefault(parts[0].lower(), parts[1].strip())
    return cfg


def _csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def _f(title, sev, desc, evidence, reco, source, conf=Confidence.HIGH, category="authentication"):
    return Finding(title=title, category=category, severity=sev, description=desc,
                   evidence=evidence, recommendation=reco, source=source, confidence=conf)


def _effective_checks(eff: dict[str, str]) -> list[Finding]:
    out: list[Finding] = []

    ciphers = [c for c in _csv(eff.get("ciphers", ""))
               if any(m in c.lower() for m in _WEAK_CIPHER_MARKERS)]
    if ciphers:
        out.append(_f(
            "SSH: cifrari deboli abilitati", Severity.MEDIUM,
            "Il server accetta cifrari considerati deboli o obsoleti (CBC, 3DES, RC4, Blowfish).",
            ", ".join(ciphers),
            "Limitare Ciphers a quelli moderni (chacha20-poly1305, aes-gcm, aes-ctr).",
            "ssh-config:weak-ciphers", category="network"))

    macs = _csv(eff.get("macs", ""))
    strong_loss = [m for m in macs if "md5" in m.lower() or m.lower().startswith("umac-64")
                   or m.lower().endswith("-96")]
    sha1 = [m for m in macs if m.lower() in ("hmac-sha1", "hmac-sha1-etm@openssh.com")]
    if strong_loss:
        out.append(_f(
            "SSH: algoritmi MAC deboli abilitati", Severity.MEDIUM,
            "Il server accetta algoritmi MAC basati su MD5 o con tag troncati.",
            ", ".join(strong_loss), "Limitare MACs a quelli -etm con SHA-2 (hmac-sha2-256/512-etm).",
            "ssh-config:weak-macs", category="network"))
    elif sha1:
        out.append(_f(
            "SSH: MAC basato su SHA-1 abilitato", Severity.LOW,
            "Il server accetta HMAC-SHA1: ancora diffuso, ma si raccomanda SHA-2.",
            ", ".join(sha1), "Preferire hmac-sha2-256/512-etm.",
            "ssh-config:sha1-macs", Confidence.MEDIUM, category="network"))

    kex = [k for k in _csv(eff.get("kexalgorithms", "")) if k in _WEAK_KEX]
    if kex:
        out.append(_f(
            "SSH: scambio di chiavi debole abilitato", Severity.MEDIUM,
            "Il server accetta algoritmi di scambio chiavi basati su SHA-1 o su gruppi piccoli.",
            ", ".join(kex), "Limitare KexAlgorithms a curve25519 e ai gruppi DH moderni.",
            "ssh-config:weak-kex", category="network"))

    try:
        tries = int(eff.get("maxauthtries", ""))
    except ValueError:
        tries = 0
    if tries > 4:
        out.append(_f(
            f"SSH: MaxAuthTries troppo alto ({tries})", Severity.LOW,
            "Ogni connessione può tentare molte password prima di essere chiusa.",
            f"MaxAuthTries {tries}", "Impostare MaxAuthTries 3 o 4.",
            "ssh-config:max-auth-tries"))

    for key, bad, sev, title, desc in (
        ("permituserenvironment", ("yes",), Severity.HIGH, "SSH: PermitUserEnvironment abilitato",
         "Gli utenti possono impostare variabili d'ambiente che aggirano restrizioni (es. LD_PRELOAD)."),
        ("hostbasedauthentication", ("yes",), Severity.HIGH, "SSH: HostbasedAuthentication abilitato",
         "L'accesso basato sull'host fidato è debole: basta compromettere un'altra macchina."),
        ("gatewayports", ("yes", "clientspecified"), Severity.MEDIUM, "SSH: GatewayPorts abilitato",
         "I tunnel SSH possono esporre porte a tutta la rete."),
        ("permittunnel", ("yes", "point-to-point", "ethernet"), Severity.LOW, "SSH: PermitTunnel abilitato",
         "Sono consentiti tunnel di rete a livello 2/3 tramite SSH."),
    ):
        val = eff.get(key, "").lower()
        if val in bad:
            out.append(_f(title, sev, desc, f"{key} {val}", f"Impostare {key} no se non serve.",
                          f"ssh-config:{key}", category="network"))

    if "allowusers" not in eff and "allowgroups" not in eff:
        out.append(_f(
            "SSH: nessuna restrizione sugli utenti ammessi", Severity.INFO,
            "Qualunque utente con una shell di login può provare ad accedere via SSH.",
            "AllowUsers/AllowGroups non impostati",
            "Valutare AllowUsers o AllowGroups per limitare chi può collegarsi.",
            "ssh-config:no-allowusers", Confidence.MEDIUM))

    try:
        alive = int(eff.get("clientaliveinterval", "0"))
    except ValueError:
        alive = 0
    if alive == 0:
        out.append(_f(
            "SSH: sessioni inattive non chiuse", Severity.LOW,
            "Senza ClientAliveInterval le sessioni abbandonate restano aperte a tempo indeterminato.",
            "ClientAliveInterval 0",
            "Impostare ClientAliveInterval 300 e ClientAliveCountMax 2.",
            "ssh-config:client-alive", Confidence.MEDIUM))
    return out
