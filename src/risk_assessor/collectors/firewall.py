"""Firewall: c'è un filtro sul traffico in ingresso? (sola lettura)

Conta come firewall solo ciò che filtra davvero l'INGRESSO della macchina:
- ufw o firewalld attivi;
- una catena nftables agganciata a `input` con policy drop o regole drop/reject;
- la catena INPUT di iptables con policy DROP/REJECT o regole DROP/REJECT.

Le regole che Docker (o una VPN) crea per il NAT e l'inoltro dei container NON proteggono
l'host: contarle come "firewall attivo" sarebbe un falso "tutto a posto", frequente proprio
sui server che ospitano applicazioni in container.
"""
from __future__ import annotations

import re

from risk_assessor.collectors._platform import install_hint, service_active, unverifiable
from risk_assessor.collectors._privileged import run_privileged
from risk_assessor.executor import BaseExecutor
from risk_assessor.host import host_info
from risk_assessor.models import Finding, Severity, Confidence
from risk_assessor.tools.base import find_tool

# Una regola "pigliatutto" nftables: solo contatori/log e poi drop o reject, senza
# condizioni (per esempio "counter reject with icmpx type admin-prohibited").
_NFT_CATCH_ALL = re.compile(
    r"^(counter(\s+packets\s+\d+\s+bytes\s+\d+)?\s+)?(log(\s+prefix\s+\"[^\"]*\")?[^;]*?\s+)?"
    r"(drop|reject)(\s+with\s+.+)?$", re.IGNORECASE)
_ANY = ("0.0.0.0/0", "::/0", "anywhere")


def nft_input_filter(ruleset: str) -> list[str]:
    """Catene nftables in ingresso che filtrano davvero ([] se nessuna).

    Conta solo una policy drop/reject o una regola finale drop/reject senza condizioni:
    regole mirate (ct state invalid drop, i set di fail2ban, docker) non rendono il
    sistema protetto, perché tutto il resto passa comunque.
    """
    evidence: list[str] = []
    for chunk in re.split(r"(?m)^\s*chain\s+", ruleset)[1:]:
        body = chunk.split("\n}", 1)[0]
        if not re.search(r"hook\s+input\b", body):
            continue
        name = chunk.split(None, 1)[0]
        policy = re.search(r"policy\s+(\w+)", body)
        catch_all = [ln.strip() for ln in body.splitlines()
                     if _NFT_CATCH_ALL.match(ln.strip().rstrip(";").strip())]
        if policy and policy.group(1).lower() in ("drop", "reject"):
            evidence.append(f"chain {name}: policy {policy.group(1)}")
        elif catch_all:
            evidence.append(f"chain {name}: regola finale '{catch_all[-1]}'")
    return evidence


def iptables_input_filter(listing: str) -> list[str]:
    """Policy DROP/REJECT o regola DROP/REJECT senza condizioni in `iptables -L INPUT -n`."""
    lines = listing.splitlines()
    evidence: list[str] = []
    if lines and re.search(r"policy\s+(DROP|REJECT)", lines[0]):
        evidence.append(lines[0].strip())
    for ln in lines[1:]:
        cols = ln.split()
        # target prot opt source destination [condizioni]
        if len(cols) < 5 or cols[0] not in ("DROP", "REJECT"):
            continue
        extra = cols[5:]
        if (cols[1] in ("all", "0") and cols[3] in _ANY and cols[4] in _ANY
                and (not extra or extra[0] == "reject-with")):
            evidence.append(ln.strip())
    return evidence


class FirewallCollector:
    name = "firewall"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        # Motivi per cui non possiamo escludere un firewall (permessi, errori inattesi).
        # Un "Nessun firewall" HIGH è lecito SOLO se tutti i controlli sono conclusivi.
        unclear: list[str] = []
        ufw_inactive: Finding | None = None

        # ufw sta in /usr/sbin: via SSH un utente normale non lo ha nel PATH.
        ufw = find_tool(executor, "ufw")
        if ufw:
            res = run_privileged(executor, [ufw, "status"])
            low = res.out.lower()
            if res.ok and "status: active" in low:
                return [self._active("ufw", res.out)]
            if res.ok and "status: inactive" in low:
                # Spento: si controlla comunque se l'ingresso è filtrato in altro modo.
                ufw_inactive = self._ufw_inactive(res.out)
            else:
                unclear.append("ufw status: " + (self._reason(res) if not res.ok else "output non riconosciuto"))

        if service_active(executor, "firewalld"):
            return [self._active("firewalld", "firewalld: active")]

        res = run_privileged(executor, ["nft", "list", "ruleset"])
        if res.ok:
            evidence = nft_input_filter(res.out)
            if evidence:
                return [self._active("nftables", "\n".join(evidence))]
        elif res.inconclusive:
            unclear.append(f"nft list ruleset: {self._reason(res)}")

        res = run_privileged(executor, ["iptables", "-L", "INPUT", "-n"])
        if res.ok:
            evidence = iptables_input_filter(res.out)
            if evidence:
                return [self._active("iptables", "\n".join(evidence[:10]))]
        elif res.inconclusive:
            unclear.append(f"iptables -L INPUT -n: {self._reason(res)}")

        if ufw_inactive is not None:
            return [ufw_inactive]
        if unclear:
            return [self._undetermined(unclear)]

        host = host_info(executor)
        if host.container:
            # Dentro un container il traffico in ingresso lo filtra l'host (o la rete dei container):
            # "nessun firewall" qui non dice nulla sulla macchina reale.
            return [unverifiable(
                "Firewall non verificabile dentro un container",
                f"Il sistema è un container ({host.container}): il firewall è quello dell'host e da qui "
                "non si vede. Va controllato sull'host.",
                "ufw/firewalld non attivi nel container; nessuna regola di input nel suo namespace",
                "firewall:container", "firewall")]
        suggested = {"debian": "ufw", "fedora": "firewalld", "rhel": "firewalld",
                     "suse": "firewalld", "arch": "ufw", "alpine": "awall"}.get(host.family, "ufw")
        return [Finding(
            title="Nessun firewall attivo rilevato",
            category="firewall",
            severity=Severity.HIGH,
            description=("Nessun filtro sul traffico in ingresso: né ufw o firewalld attivi, né regole "
                         "nftables/iptables che blocchino qualcosa in input. Le eventuali regole di "
                         "Docker servono al NAT dei container e non proteggono l'host."),
            evidence="ufw/firewalld non attivi; catene input senza policy drop né regole drop/reject.",
            recommendation=f"Installare e configurare un firewall ({suggested} su questo sistema).",
            source="firewall:none",
            confidence=Confidence.MEDIUM,
            command=install_hint(host, suggested),
        )]

    @staticmethod
    def _ufw_inactive(out: str) -> Finding:
        return Finding(
            title="Firewall ufw installato ma inattivo",
            category="firewall",
            severity=Severity.HIGH,
            description="ufw è installato ma non attivo, e nessun'altra regola filtra il traffico in ingresso.",
            evidence=out.strip()[:500],
            recommendation="Attivare ufw con 'ufw enable'",
            command="sudo ufw allow 22/tcp && sudo ufw enable",
            source="firewall:ufw-inactive",
            confidence=Confidence.HIGH,
        )

    @staticmethod
    def _reason(res) -> str:
        text = (res.err or res.out).strip().splitlines()
        return text[0][:150] if text else f"codice di uscita {res.rc}"

    @staticmethod
    def _undetermined(details: list[str]) -> Finding:
        return Finding(
            title="Stato del firewall non determinabile",
            category="firewall",
            severity=Severity.INFO,
            description=(
                "I comandi per leggere le regole del firewall richiedono privilegi che "
                "l'assessment non aveva: non si può dire né che il firewall ci sia né che manchi."
            ),
            evidence="; ".join(details)[:500],
            recommendation=(
                "Rieseguire l'assessment come root o con un utente che possa usare "
                "'sudo -n' in sola lettura (nft/iptables/ufw), oppure verificare a mano."
            ),
            source="firewall:undetermined",
            confidence=Confidence.LOW,
        )

    def _active(self, name: str, evidence: str) -> Finding:
        return Finding(
            title=f"Firewall attivo: {name}",
            category="firewall",
            severity=Severity.INFO,
            description=f"Rilevato firewall attivo: {name}",
            evidence=evidence.strip()[:500],
            recommendation="Nessuna azione richiesta.",
            source=f"firewall:{name}-active",
            confidence=Confidence.HIGH,
        )
