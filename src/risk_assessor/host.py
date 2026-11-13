"""Riconoscimento del sistema analizzato: piattaforma, distribuzione, gestore pacchetti, init.

Tutti i controlli e i tool hanno bisogno delle stesse informazioni (che Linux è, quale
gestore di pacchetti usa, se gira systemd...). Le raccoglie un solo comando all'inizio
dell'assessment, il cui risultato resta in memoria sull'Executor: via SSH questo evita
decine di round-trip.

Non si usa `which`: manca in molte immagini minime (Fedora, Rocky, Alma, openSUSE, Arch).
Si usa `command -v`, che è un builtin di ogni shell POSIX.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from risk_assessor.executor import BaseExecutor

# Famiglie di distribuzioni: decidono gestore dei pacchetti, nomi dei pacchetti e consigli.
FAMILY_IDS: dict[str, frozenset[str]] = {
    "debian": frozenset({"debian", "ubuntu", "linuxmint", "pop", "kali", "raspbian", "elementary",
                         "zorin", "neon", "devuan", "parrot", "mx"}),
    "fedora": frozenset({"fedora"}),
    "rhel": frozenset({"rhel", "centos", "rocky", "almalinux", "ol", "amzn", "scientific",
                       "eurolinux", "cloudlinux", "circle", "navylinux"}),
    "suse": frozenset({"opensuse", "opensuse-leap", "opensuse-tumbleweed", "opensuse-microos",
                       "sles", "sled", "sle-micro", "suse"}),
    "arch": frozenset({"arch", "archarm", "manjaro", "endeavouros", "garuda", "artix", "cachyos"}),
    "alpine": frozenset({"alpine", "postmarketos"}),
}

FAMILY_LABEL = {
    "debian": "Debian e derivate", "fedora": "Fedora", "rhel": "RHEL e derivate",
    "suse": "SUSE / openSUSE", "arch": "Arch e derivate", "alpine": "Alpine",
    "macos": "macOS", "unknown": "sconosciuta",
}

# Gestore dei pacchetti preferito per famiglia (il primo presente vince).
_PREFERRED_PM = {
    "debian": ("apt-get",), "fedora": ("dnf", "yum"), "rhel": ("dnf", "yum"),
    "suse": ("zypper",), "arch": ("pacman",), "alpine": ("apk",), "macos": ("brew",),
}
_ALL_PM = ("apt-get", "dnf", "yum", "zypper", "pacman", "apk", "brew")

# Comandi di cui conviene conoscere subito la presenza (gli altri si chiedono al bisogno).
PROBED_COMMANDS = (
    "apt-get", "dnf", "yum", "zypper", "pacman", "apk",
    "systemctl", "rc-service", "rc-status", "sv",
    "ss", "netstat", "lsof", "sudo", "sysctl",
)

# Un unico script di sola lettura, senza dati esterni: niente rischio di injection.
_DETECT_SCRIPT = r"""
printf '%s\n' "system=$(uname -s 2>/dev/null)"
printf '%s\n' "machine=$(uname -m 2>/dev/null)"
printf '%s\n' "uid=$(id -u 2>/dev/null)"
if [ -r /etc/os-release ]; then
  while IFS= read -r l || [ -n "$l" ]; do printf '%s\n' "osr.$l"; done < /etc/os-release
fi
if command -v sw_vers >/dev/null 2>&1; then
  printf '%s\n' "mac.version=$(sw_vers -productVersion 2>/dev/null)"
fi
for c in __COMMANDS__; do
  p=$(command -v "$c" 2>/dev/null) && printf '%s\n' "cmd.$c=$p"
done
for b in /opt/homebrew/bin/brew /usr/local/bin/brew; do
  if [ -x "$b" ]; then printf '%s\n' "cmd.brew=$b"; break; fi
done
[ -d /run/systemd/system ] && printf '%s\n' "systemd_running=1"
[ -d /run/openrc ] && printf '%s\n' "openrc_running=1"
[ -r /proc/1/comm ] && printf '%s\n' "pid1=$(cat /proc/1/comm 2>/dev/null)"
[ -f /.dockerenv ] && printf '%s\n' "container=docker"
[ -f /run/.containerenv ] && printf '%s\n' "container=podman"
[ -r /run/systemd/container ] && printf '%s\n' "container=$(cat /run/systemd/container 2>/dev/null)"
printf '%s\n' "probe=ok"
""".replace("__COMMANDS__", " ".join(PROBED_COMMANDS))


@dataclass(frozen=True)
class HostInfo:
    """Cosa sappiamo del target. `commands is None` = rilevamento fallito (si chiede al bisogno)."""

    system: str = "unknown"            # linux | darwin | unknown
    distro_id: str = ""                # ubuntu, rocky, alpine, macos...
    id_like: tuple[str, ...] = ()
    version: str = ""                  # VERSION_ID (o versione di macOS)
    codename: str = ""                 # VERSION_CODENAME (es. bookworm)
    pretty: str = ""                   # nome leggibile
    family: str = "unknown"            # debian | fedora | rhel | suse | arch | alpine | macos | unknown
    package_manager: str | None = None
    init: str = "unknown"              # systemd | openrc | runit | launchd | unknown
    container: str = ""                # docker, podman, lxc... ("" = non rilevato)
    machine: str = ""
    uid: str = ""
    commands: dict[str, str] | None = field(default=None, compare=False)

    @property
    def is_linux(self) -> bool:
        return self.system == "linux"

    @property
    def is_macos(self) -> bool:
        return self.system == "darwin"

    @property
    def is_root(self) -> bool:
        return self.uid == "0"

    @property
    def family_label(self) -> str:
        return FAMILY_LABEL.get(self.family, self.family)

    @property
    def platform_label(self) -> str:
        return "macOS" if self.is_macos else "Linux" if self.is_linux else "sconosciuta"

    def to_dict(self) -> dict:
        return {
            "platform": self.system, "distro": self.distro_id, "version": self.version,
            "name": self.pretty, "family": self.family, "package_manager": self.package_manager,
            "init": self.init, "container": self.container or None, "architecture": self.machine,
        }


def _family(distro_id: str, id_like: tuple[str, ...]) -> str:
    for candidate in (distro_id, *id_like):
        for fam, ids in FAMILY_IDS.items():
            if candidate in ids:
                return fam
    return "unknown"


def parse_detection(text: str) -> HostInfo:
    """Interpreta l'output di _DETECT_SCRIPT (funzione pura, usata anche nei test)."""
    values: dict[str, str] = {}
    osr: dict[str, str] = {}
    commands: dict[str, str] = {}
    containers: list[str] = []
    for line in (text or "").splitlines():
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        # A parità di chiave vale la prima (os-release non ripete le chiavi; una riga
        # duplicata non deve sovrascrivere un valore già letto).
        if key.startswith("osr."):
            osr.setdefault(key[4:], value.strip().strip('"').strip("'"))
        elif key.startswith("cmd."):
            if value.strip():
                commands.setdefault(key[4:], value.strip())
        elif key == "container":
            if value.strip():
                containers.append(value.strip())
        else:
            values.setdefault(key, value.strip())

    if values.get("probe") != "ok":
        return HostInfo()

    uname = values.get("system", "").lower()
    system = "linux" if uname == "linux" else "darwin" if uname == "darwin" else "unknown"

    if system == "darwin":
        version = values.get("mac.version", "")
        distro_id, id_like, codename = "macos", (), ""
        pretty = f"macOS {version}".strip()
        family = "macos"
    else:
        distro_id = osr.get("ID", "").lower()
        id_like = tuple(osr.get("ID_LIKE", "").lower().split())
        version = osr.get("VERSION_ID", "")
        codename = osr.get("VERSION_CODENAME", "")
        pretty = osr.get("PRETTY_NAME") or " ".join(x for x in (osr.get("NAME", ""), version) if x)
        family = _family(distro_id, id_like) if system == "linux" else "unknown"

    pm = None
    for name in _PREFERRED_PM.get(family, ()) + _ALL_PM:
        if name in commands:
            pm = "apt" if name == "apt-get" else name
            break

    pid1 = values.get("pid1", "")
    if system == "darwin":
        init = "launchd"
    elif values.get("systemd_running") == "1":
        init = "systemd"
    elif values.get("openrc_running") == "1" or pid1 == "openrc-init":
        init = "openrc"
    elif pid1 in ("runit", "runit-init"):
        init = "runit"
    else:
        init = "unknown"

    return HostInfo(
        system=system, distro_id=distro_id, id_like=id_like, version=version,
        codename=codename, pretty=pretty or system, family=family, package_manager=pm,
        init=init, container=containers[0] if containers else "",
        machine=values.get("machine", ""), uid=values.get("uid", ""), commands=commands,
    )


_ATTR = "_watchdog_host_info"


def host_info(executor: BaseExecutor) -> HostInfo:
    """Rileva il target al primo uso e poi riusa il risultato (uno per Executor)."""
    cached = getattr(executor, _ATTR, None)
    if isinstance(cached, HostInfo):
        return cached
    out, _, _ = executor.execute_command(["sh", "-c", _DETECT_SCRIPT], timeout=30)
    info = parse_detection(out)
    set_host_info(executor, info)
    return info


def set_host_info(executor: BaseExecutor, info: HostInfo) -> None:
    """Imposta (o sostituisce) le informazioni sul target, per esempio nei test."""
    try:
        setattr(executor, _ATTR, info)
    except AttributeError:
        pass


def command_path(executor: BaseExecutor, name: str) -> str | None:
    """Percorso di un comando sul target, o None. Non dipende da `which`."""
    info = host_info(executor)
    if info.commands is not None and name in PROBED_COMMANDS:
        return info.commands.get(name)
    if info.commands is not None and name == "brew":
        return info.commands.get("brew")
    # Il nome è passato come argomento ($1), non concatenato nello script.
    out, _, rc = executor.execute_command(["sh", "-c", 'command -v "$1"', "sh", name])
    path = (out or "").strip().splitlines()
    if rc == 0 and path and path[0].strip():
        return path[0].strip()
    return None


def has_command(executor: BaseExecutor, name: str) -> bool:
    return command_path(executor, name) is not None


_PRIV_ATTR = "_watchdog_privileges"


def privileges(executor: BaseExecutor) -> list[str] | None:
    """Come ottenere i privilegi di root sul target.

    [] se siamo già root, ["sudo", "-n"] se sudo funziona senza password,
    None se non è possibile (i comandi girano senza privilegi o vanno saltati).
    Il risultato resta in memoria per tutto l'assessment.
    """
    cached = getattr(executor, _PRIV_ATTR, "unset")
    if cached != "unset":
        return list(cached) if cached is not None else None
    if host_info(executor).is_root:
        result: list[str] | None = []
    else:
        _, _, rc = executor.execute_command(["sudo", "-n", "true"])
        result = ["sudo", "-n"] if rc == 0 else None
    try:
        setattr(executor, _PRIV_ATTR, result)
    except AttributeError:
        pass
    return list(result) if result is not None else None


def privileged_prefix(executor: BaseExecutor) -> list[str]:
    """Prefisso per un comando che rende di più con i privilegi ma funziona anche senza."""
    return privileges(executor) or []
