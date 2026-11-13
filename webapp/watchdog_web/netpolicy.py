"""Quali macchine si possono analizzare.

Un analista non deve poter usare WatchDog per collegarsi a qualunque indirizzo: di
default solo alle reti private del laboratorio (configurabili con
WATCHDOG_ALLOWED_NETWORKS), mai al Raspberry stesso (loopback), agli indirizzi
link-local (169.254.x.x, dove su alcune piattaforme risponde il servizio dei metadati)
né ai servizi di WatchDog (database, applicazione web).

Il controllo si fa due volte: quando si salva l'obiettivo e, di nuovo, quando parte
la scansione, risolvendo il nome in quel momento e collegandosi all'indirizzo
controllato (così un nome DNS non può cambiare indirizzo nel frattempo).
"""
from __future__ import annotations

import ipaddress
import socket


class HostNotAllowed(ValueError):
    """L'obiettivo non è tra quelli consentiti: il messaggio spiega perché."""


def _ip(value: str):
    try:
        ip = ipaddress.ip_address(value.strip("[]").split("%", 1)[0])
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip


def _resolve(name: str) -> list:
    try:
        infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    out = []
    for info in infos:
        ip = _ip(info[4][0])
        if ip is not None and ip not in out:
            out.append(ip)
    return out


def _check_ip(ip, allowed_networks) -> None:
    if ip.is_loopback or ip.is_unspecified:
        raise HostNotAllowed(f"{ip} è la macchina su cui gira WatchDog stesso: non è un obiettivo valido.")
    if ip.is_link_local or ip.is_multicast or ip.is_reserved:
        raise HostNotAllowed(f"{ip} è un indirizzo speciale (link-local, multicast o riservato): non è un obiettivo valido.")
    if not any(ip.version == net.version and ip in net for net in allowed_networks):
        nets = ", ".join(str(n) for n in allowed_networks)
        raise HostNotAllowed(f"{ip} è fuori dalle reti che WatchDog può analizzare ({nets}). "
                             "Un amministratore può cambiarle con WATCHDOG_ALLOWED_NETWORKS nel file .env.")


def check_host(host: str, allowed_networks, denied_hosts, *, resolve: bool) -> list[str]:
    """Controlla l'obiettivo e restituisce gli indirizzi a cui collegarsi.

    Con resolve=False (quando si salva l'obiettivo dall'applicazione web, che non ha accesso
    alla rete esterna) i nomi si controllano solo contro l'elenco dei vietati e vengono
    risolti e verificati al momento della scansione. Solleva HostNotAllowed.
    """
    host = host.strip()
    lowered = host.lower().rstrip(".")
    if lowered in denied_hosts or lowered == "localhost" or lowered.endswith(".localhost"):
        raise HostNotAllowed(f"«{host}» è un servizio di WatchDog o la macchina stessa: non è un obiettivo valido.")
    literal = _ip(host)
    if literal is not None:
        ips = [literal]
    elif not resolve:
        return []
    else:
        ips = _resolve(host)
        if not ips:
            raise HostNotAllowed(f"Il nome «{host}» non si risolve in nessun indirizzo: controlla il nome o usa l'indirizzo IP.")
    for ip in ips:
        _check_ip(ip, allowed_networks)
    if resolve or literal is not None:
        services = {ip for name in denied_hosts for ip in _resolve(name)}
        for ip in ips:
            if ip in services:
                raise HostNotAllowed(f"{ip} è l'indirizzo di un servizio di WatchDog: non è un obiettivo valido.")
    return [str(ip) for ip in ips]
