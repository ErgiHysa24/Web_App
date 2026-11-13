"""Native Linux information collector.
    
Leve le informazioni tramite Executor (locale o SSH) e produce Finding.
Non accede mai direttamente al filesystem.
"""
from __future__ import annotations

from risk_assessor.models import Finding, Severity, Confidence
from risk_assessor.executor import BaseExecutor


class LinuxCollector:
    """Collects basic system information: OS, kernel, hostname, arch."""

    name = "linux"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        """Collect basic system information via Executor.
        
        Args:
            executor: The executor to use for running commands.
            
        Returns:
            List of Finding objects containing collected information.
        """
        findings: list[Finding] = []
        info = self._collect_info(executor)
        if info:
            findings.append(self._info_finding(info))
        return findings

    def _collect_info(self, executor: BaseExecutor) -> dict[str, str]:
        """Collect system information using Executor.
        
        Args:
            executor: The executor to use for running commands.
            
        Returns:
            Dictionary of system info {key: value}.
        """
        info: dict[str, str] = {}

        # hostname
        res = executor.execute_command(["hostname"])
        if res[2] == 0 and res[0].strip():
            info["hostname"] = res[0].strip()

        # kernel version
        res = executor.execute_command(["uname", "-r"])
        if res[2] == 0 and res[0].strip():
            info["kernel"] = res[0].strip()

        # architecture
        res = executor.execute_command(["uname", "-m"])
        if res[2] == 0 and res[0].strip():
            info["architecture"] = res[0].strip()

        # OS release
        res = executor.execute_command(["cat", "/etc/os-release"])
        if res[2] == 0:
            parsed = self._parse_os_release(res[0])
            if "NAME" in parsed:
                info["os_name"] = parsed["NAME"]
            if "VERSION_ID" in parsed:
                info["os_version"] = parsed["VERSION_ID"]
            if "ID" in parsed:
                info["os_id"] = parsed["ID"]

        return info

    @staticmethod
    def _parse_os_release(text: str) -> dict[str, str]:
        """Parse the KEY=VALUE format of /etc/os-release."""
        result: dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip().strip('"').strip("'")
            result[key.strip()] = value
        return result

    @staticmethod
    def _info_finding(info: dict[str, str]) -> Finding:
        """Create a Finding from collected system information.
        
        Args:
            info: Dictionary of system info.
            
        Returns:
            Finding object with summary and evidence.
        """
        parts = []
        if "os_name" in info:
            parts.append(info["os_name"])
        if "os_version" in info:
            parts.append(info["os_version"])
        if "kernel" in info:
            parts.append(f"kernel {info['kernel']}")
        if "architecture" in info:
            parts.append(info["architecture"])

        summary = ", ".join(parts) if parts else "informazioni non disponibili"

        evidence_lines = [f"{k}: {v}" for k, v in sorted(info.items())]
        evidence = "\n".join(evidence_lines) if evidence_lines else "nessuna informazione raccolta"

        return Finding(
            title="Informazioni di sistema",
            category="system_info",
            severity=Severity.INFO,
            description=f"Sistema rilevato: {summary}",
            evidence=evidence[:500],
            recommendation="Nessuna azione richiesta.",
            source="linux-check:linux",
            confidence=Confidence.HIGH,
        )
