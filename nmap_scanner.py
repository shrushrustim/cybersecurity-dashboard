"""
nmap_scanner.py — Real Nmap execution via subprocess + result parser.
WARNING: Only scan hosts you own or have explicit permission to test.
"""

import re
import subprocess
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

SCAN_TYPES = {
    "quick":   {"label": "Quick Scan (-F)",          "flags": ["-F", "-T4"]},
    "ping":    {"label": "Ping Scan (-sn)",           "flags": ["-sn"]},
    "full":    {"label": "Full Scan (-sV)",           "flags": ["-sV", "-T4"]},
    "ports":   {"label": "Top 1000 Ports",            "flags": ["-T4", "--top-ports", "1000"]},
    "os":      {"label": "OS Detection (-O)",         "flags": ["-O", "-T4"]},
    "scripts": {"label": "Default Scripts (-sC)",     "flags": ["-sC", "-sV", "-T4"]},
}


def nmap_available() -> bool:
    """Check if nmap is installed on the system."""
    try:
        r = subprocess.run(["nmap", "--version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def run_nmap_scan(target: str, scan_type: str = "quick", timeout: int = 45) -> Dict:
    """
    Run an nmap scan and return structured results.

    Returns:
        {
            "success": bool,
            "target": str,
            "scan_type": str,
            "raw_output": str,
            "hosts": [{"host": str, "state": str, "ports": [...]}],
            "error": str or None
        }
    """
    if not target or not target.strip():
        return {"success": False, "error": "No target specified", "hosts": [], "raw_output": ""}

    # Basic safety: strip dangerous shell chars
    clean_target = re.sub(r"[;&|`$<>()\\]", "", target.strip())
    if not clean_target:
        return {"success": False, "error": "Invalid target", "hosts": [], "raw_output": ""}

    if not nmap_available():
        return {
            "success": False,
            "error": "nmap is not installed. Install it with: brew install nmap (macOS) or apt install nmap (Linux)",
            "hosts": [], "raw_output": "",
        }

    flags = SCAN_TYPES.get(scan_type, SCAN_TYPES["quick"])["flags"]
    cmd = ["nmap"] + flags + [clean_target]

    logger.info(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        raw = result.stdout + result.stderr
        hosts = _parse_nmap_output(raw)
        return {
            "success": True,
            "target": clean_target,
            "scan_type": scan_type,
            "raw_output": raw,
            "hosts": hosts,
            "error": None,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Scan timed out after {timeout}s. Try a quicker scan type.",
            "hosts": [], "raw_output": "",
        }
    except Exception as e:
        return {"success": False, "error": str(e), "hosts": [], "raw_output": ""}


def _parse_nmap_output(raw: str) -> List[Dict]:
    """Parse nmap text output into structured host/port records."""
    hosts = []
    current_host = None

    for line in raw.splitlines():
        # New host
        host_match = re.match(r"Nmap scan report for (.+)", line)
        if host_match:
            current_host = {
                "host": host_match.group(1).strip(),
                "state": "up",
                "ports": [],
                "os": "",
                "mac": "",
            }
            hosts.append(current_host)
            continue

        if current_host is None:
            continue

        # Host state
        state_match = re.match(r"Host is (\w+)", line)
        if state_match:
            current_host["state"] = state_match.group(1)
            continue

        # Port line: 22/tcp   open  ssh     OpenSSH 8.9
        port_match = re.match(
            r"(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)", line
        )
        if port_match:
            current_host["ports"].append({
                "port":    port_match.group(1),
                "proto":   port_match.group(2),
                "state":   port_match.group(3),
                "service": port_match.group(4),
                "version": port_match.group(5).strip(),
            })
            continue

        # OS detection
        os_match = re.match(r"OS details: (.+)", line)
        if os_match and current_host:
            current_host["os"] = os_match.group(1)

        # MAC address
        mac_match = re.match(r"MAC Address: ([A-F0-9:]+) \((.+)\)", line)
        if mac_match and current_host:
            current_host["mac"] = f"{mac_match.group(1)} ({mac_match.group(2)})"

    return hosts
