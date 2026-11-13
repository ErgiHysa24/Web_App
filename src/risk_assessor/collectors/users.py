"""Users and groups collector."""
from __future__ import annotations

from risk_assessor.collectors._privileged import run_privileged
from risk_assessor.executor import BaseExecutor
from risk_assessor.sanitize import safe_shell_arg
from risk_assessor.models import Finding, Severity, Confidence


class UsersCollector:
    name = "users"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        """Collect user and group information via Executor.
        
        Args:
            executor: The executor to use for running commands.
            
        Returns:
            List of Finding objects containing collected information.
        """
        findings: list[Finding] = []
        
        # Read /etc/passwd
        passwd_text = self._read(executor, ["cat", "/etc/passwd"])
        if passwd_text:
            findings.extend(self._check_uid_zero(passwd_text))
            findings.extend(self._check_login_users(passwd_text))
        
        # Read /etc/shadow for password checks
        # (di norma leggibile solo da root: se non lo è, il report DEVE dirlo,
        # altrimenti "nessun account senza password" sarebbe una falsa rassicurazione)
        shadow = run_privileged(executor, ["cat", "/etc/shadow"])
        if shadow.ok:
            if shadow.out:
                findings.extend(self._check_empty_passwords(shadow.out, passwd_text))
        elif shadow.inconclusive:
            findings.append(self._shadow_unreadable(shadow))
        
        # Check privileged groups
        findings.extend(self._check_privileged_groups(executor))
        
        return findings

    @staticmethod
    def _shadow_unreadable(res) -> Finding:
        detail = (res.err or res.out).strip().splitlines()
        return Finding(
            title="Controllo password non eseguito: /etc/shadow non leggibile",
            category="authentication",
            severity=Severity.INFO,
            description=(
                "Senza privilegi non si può leggere /etc/shadow, quindi NON è stato "
                "verificato se esistono account senza password."
            ),
            evidence=(detail[0][:200] if detail else f"codice di uscita {res.rc}"),
            recommendation=(
                "Rieseguire l'assessment come root o con 'sudo -n' disponibile "
                "(NOPASSWD per 'cat /etc/shadow'), oppure controllare a mano."
            ),
            source="users-collector:shadow-unreadable",
            confidence=Confidence.LOW,
        )

    @staticmethod
    def _read(executor, cmd) -> str:
        """Execute command and return stdout if successful."""
        out, err, rc = executor.execute_command(cmd)
        return out if rc == 0 else ""

    def _check_uid_zero(self, passwd: str) -> list[Finding]:
        """Find users with UID 0 other than root.
        
        Args:
            passwd: Content of /etc/passwd.
            
        Returns:
            List of HIGH severity findings for unexpected UID 0 users.
        """
        findings = []
        lines = passwd.strip().splitlines()
        
        for line in lines:
            fields = line.split(":")
            if len(fields) >= 3:
                try:
                    user = fields[0]
                    uid = int(fields[2])
                    
                    # Check UID 0 and not root
                    if uid == 0 and user != "root":
                        findings.append(Finding(
                            title=f"Utente con UID 0 non-root: {user}",
                            category="users",
                            severity=Severity.HIGH,
                            description=f"L'utente '{user}' ha un ID utente (UID) di 0, riservato a root.",
                            evidence=line.strip(),
                            recommendation="Verificare se questo account è autorizzato.",
                            source="users-collector:uid-zero",
                            confidence=Confidence.HIGH,
                        ))
                except ValueError:
                    # Invalid UID field, skip
                    continue
        
        return findings

    def _check_login_users(self, passwd: str) -> list[Finding]:
        """Find users with valid login shells and UID < 1000 (excluding system accounts).
        
        Args:
            passwd: Content of /etc/passwd.
            
        Returns:
            List of INFO severity findings for interactive login users.
        """
        findings = []
        invalid_shells = ["/sbin/nologin", "/usr/sbin/nologin", "/bin/false", "/usr/bin/false",
                          "/bin/sync", "/sbin/halt", "/sbin/shutdown"]   # non sono shell di accesso
        
        lines = passwd.strip().splitlines()
        
        for line in lines:
            fields = line.split(":")
            if len(fields) >= 7:
                try:
                    user = fields[0]
                    uid = int(fields[2])
                    shell = fields[6].strip()
                    
                    # Exclude UID 0, system accounts (UID >= 1000), and nologin shells
                    if uid == 0:
                        continue
                    if shell in invalid_shells:
                        continue
                    
                    findings.append(Finding(
                        title=f"Utente con shell di login: {user}",
                        category="users",
                        severity=Severity.INFO,
                        description=f"L'utente '{user}' può effettuare un accesso interattivo (shell: {shell}).",
                        evidence=line.strip(),
                        recommendation="Nessuna azione richiesta.",
                        source="users-collector:login-user",
                        confidence=Confidence.MEDIUM,
                    ))
                except ValueError:
                    # Invalid UID, skip
                    continue
        
        return findings

    def _check_empty_passwords(self, shadow: str, passwd: str) -> list[Finding]:
        """Find accounts with empty passwords.
        
        Args:
            shadow: Content of /etc/shadow.
            passwd: Content of /etc/passwd (for username lookup).
            
        Returns:
            List of CRITICAL severity findings for empty passwords.
        """
        findings = []
        shadow_lines = shadow.strip().splitlines()
        
        # Build user to shell mapping from passwd for evidence display
        user_shells = {}
        for line in passwd.strip().splitlines():
            fields = line.split(":")
            if len(fields) >= 7:
                try:
                    user = fields[0]
                    user_shells[user] = fields[6].strip()
                except ValueError:
                    continue
        
        # Check empty passwords in shadow
        for shadow_line in shadow_lines:
            fields = shadow_line.split(":")
            if len(fields) >= 2:
                username = fields[0]
                password_hash = fields[1]
                
                # Empty password indicated by two consecutive colons (::)
                if password_hash == "":
                    findings.append(Finding(
                        title=f"Account senza password: {username}",
                        category="authentication",
                        severity=Severity.CRITICAL,
                        description=f"L'utente '{username}' non ha una password impostata.",
                        evidence=f"{username}:<vuoto>:...",
                        recommendation="Impostare una password o bloccare l'account.",
                        source="users-collector:empty-password",
                        confidence=Confidence.HIGH,
                        command=(f"sudo passwd -l {arg}" if (arg := safe_shell_arg(username)) else ""),
                    ))
        
        return findings

    def _check_privileged_groups(self, executor) -> list[Finding]:
        """Find members of privileged groups (sudo, wheel, docker).
        
        Args:
            executor: The executor to run commands.
            
        Returns:
            List of INFO severity findings for privileged group members.
        """
        findings = []
        privileged_groups = ["sudo", "wheel", "docker"]
        
        for group_name in privileged_groups:
            try:
                cmd = ["getent", "group", group_name]
                out, err, rc = executor.execute_command(cmd)
                
                members = [m for m in out.strip().split(":")[-1].split(",") if m.strip()] if rc == 0 else []
                if members:
                    findings.append(Finding(
                        title=f"Gruppo privilegiato {group_name}: {', '.join(members)}",
                        category="privileges",
                        severity=Severity.INFO,
                        description=(f"Questi utenti sono nel gruppo '{group_name}'"
                                     + (": possono controllare Docker, e quindi la macchina, senza sudo."
                                        if group_name == "docker" else ": possono ottenere i privilegi di root.")),
                        evidence=out.strip(),
                        recommendation="Verificare che la membership sia autorizzata.",
                        source="users-collector:privileged-group",
                        confidence=Confidence.MEDIUM,
                    ))
            except Exception:
                # Command failed, continue silently
                pass
        
        return findings
