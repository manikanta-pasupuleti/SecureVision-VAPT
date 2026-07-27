from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import List, Dict, Optional
import shutil
import subprocess

try:
    import nmap  # type: ignore
except Exception:
    nmap = None


def discover_devices(targets: List[str], mode: str = "simulated") -> List[Dict]:
    """Discover devices from a list of target strings.

    targets: list of IPs or CIDRs.
    mode: 'simulated' or 'live'. Live uses nmap when available; otherwise falls back to simulated.
    """
    if mode == "live":
        live = _discover_live(targets)
        if live is not None:
            return live

    return _discover_simulated(targets)


def _discover_simulated(targets: List[str]) -> List[Dict]:
    discovered = []

    for target in targets:
        if "/" in target:
            network = ip_network(target, strict=False)
            for host in list(network.hosts())[:32]:
                discovered.append(_build_device(str(host), source=target))
        else:
            discovered.append(_build_device(target, source=target))

    return discovered


def _discover_live(targets: List[str]) -> Optional[List[Dict]]:
    """Attempt live discovery using python-nmap or the nmap binary. Returns None on failure."""
    # try python-nmap first
    if nmap:
        try:
            nm = nmap.PortScanner()
            hosts_found = []
            for target in targets:
                nm.scan(hosts=target, arguments='-sn')
                for host in nm.all_hosts():
                    if nm[host].get('status', {}).get('state') == 'up':
                        hosts_found.append(host)

            devices = []
            for h in hosts_found:
                devices.append({
                    "ip_address": h,
                    "source": ",".join(targets),
                    "discovered": True,
                })
            return devices
        except Exception:
            return None

    # fallback to system nmap binary
    nmap_bin = shutil.which('nmap')
    if not nmap_bin:
        return None

    try:
        hosts_found = []
        for target in targets:
            proc = subprocess.run([nmap_bin, '-sn', target], capture_output=True, text=True, timeout=60)
            out = proc.stdout
            for line in out.splitlines():
                line = line.strip()
                if line.startswith('Nmap scan report for'):
                    parts = line.split()
                    ip_token = parts[-1]
                    # strip parentheses or trailing characters like ')' from tokens like '(192.168.1.1)'
                    ip = ip_token.strip('() ,')
                    hosts_found.append(ip)

        devices = []
        for h in hosts_found:
            devices.append({
                "ip_address": h,
                "source": ",".join(targets),
                "discovered": True,
            })

        return devices
    except Exception:
        return None


def _build_device(ip_text, source):
    try:
        ip_address(ip_text)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address or CIDR entry: {ip_text}") from exc

    return {
        "ip_address": ip_text,
        "source": source,
        "discovered": True,
    }
