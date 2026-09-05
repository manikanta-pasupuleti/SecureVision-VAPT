from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import List, Dict

import shutil
import subprocess
import socket

from scanner.nmap_scanner import scan_host


def discover_devices(
    targets: List[str],
    mode: str = "live",
) -> List[Dict]:
    """
    Discover devices from target IP addresses, hostnames, or CIDR networks.

    Modes:
        live       -> Real Nmap discovery and service scanning.
        simulated  -> Existing simulated device profiles.

    IMPORTANT:
        Live mode NEVER falls back to simulated data.

        If Nmap fails, an exception is raised so that the problem
        is visible instead of silently generating fake devices.
    """

    if not targets:
        raise ValueError("No scan targets were provided.")

    mode = (mode or "live").strip().lower()

    print("\n========================================")
    print("        DEVICE DISCOVERY")
    print("========================================")
    print("Targets:", targets)
    print("Mode:", mode)
    print("========================================\n")

    if mode == "simulated":
        print("[DISCOVERY] Using SIMULATED device profiles.")
        return _discover_simulated(targets)

    if mode == "live":
        print("[DISCOVERY] Using REAL NMAP discovery.")
        return _discover_live(targets)

    raise ValueError(
        f"Unsupported discovery mode: {mode}. "
        f"Expected 'live' or 'simulated'."
    )


def _discover_simulated(targets: List[str]) -> List[Dict]:
    """
    Existing simulated discovery.

    This function is ONLY used when mode='simulated'.
    """

    discovered: List[Dict] = []

    for target in targets:

        target = target.strip()

        if not target:
            continue

        if "/" in target:

            network = ip_network(
                target,
                strict=False,
            )

            for host in list(network.hosts())[:32]:

                discovered.append(
                    _build_device(
                        str(host),
                        source=target,
                    )
                )

        else:

            discovered.append(
                _build_device(
                    target,
                    source=target,
                )
            )

    print(
        f"[DISCOVERY] Simulated devices discovered: "
        f"{len(discovered)}"
    )

    return discovered


def _discover_live(targets: List[str]) -> List[Dict]:
    """
    Real Nmap discovery.

    For explicit IP addresses:
        Directly call scan_host().

    For hostnames:
        Resolve all IPv4 addresses and try them one by one.
        Stop after the first reachable/usable address.

    For CIDR ranges:
        First perform host discovery with Nmap -sn,
        then run service/version detection using scan_host().

    IMPORTANT:
        This function does NOT return None on failure.

        A live scan failure must never cause the application
        to silently switch to simulated data.
    """

    nmap_bin = shutil.which("nmap")

    if not nmap_bin:
        raise RuntimeError(
            "Nmap was not found in PATH. "
            "Install Nmap or add its installation directory "
            "to the system PATH."
        )

    devices: List[Dict] = []

    for target in targets:

        target = target.strip()

        if not target:
            continue

        print(
            f"\n[DISCOVERY] Processing target: {target}"
        )

        # DIRECT IP / HOSTNAME TARGET
        if "/" not in target:

            # --------------------------------------------------
            # Direct IP address
            # --------------------------------------------------
            try:
                ip_address(target)
                resolved_ips = [target]

                print(
                    f"[DISCOVERY] Target is an IP address: "
                    f"{target}"
                )

            # --------------------------------------------------
            # Hostname
            # --------------------------------------------------
            except ValueError:

                try:
                    _, _, resolved_ips = socket.gethostbyname_ex(
                        target
                    )

                except socket.gaierror as exc:

                    raise ValueError(
                        f"Invalid IP address or hostname: {target}"
                    ) from exc

                # Remove duplicates while preserving order.
                resolved_ips = list(
                    dict.fromkeys(resolved_ips)
                )

                if not resolved_ips:
                    raise ValueError(
                        f"Hostname did not resolve to an IPv4 address: "
                        f"{target}"
                    )

                print(
                    f"[DISCOVERY] Resolved hostname: "
                    f"{target} -> {resolved_ips}"
                )

            # --------------------------------------------------
            # Try resolved addresses.
            #
            # For hostnames, this handles cases where DNS returns
            # multiple IPv4 addresses and the first one is down.
            #
            # We stop after the first successful/reachable host
            # to avoid unnecessary repeated Nmap scans.
            # --------------------------------------------------
            found_working_host = False

            for resolved_ip in resolved_ips:

                print(
                    f"[DISCOVERY] Direct live scan: "
                    f"{target} -> {resolved_ip}"
                )

                try:
                    nmap_result = scan_host(resolved_ip)

                except Exception as exc:

                    # For a hostname, try the next resolved IP.
                    if len(resolved_ips) > 1:
                        print(
                            f"[DISCOVERY] Scan failed for "
                            f"{resolved_ip}: {exc}"
                        )
                        print(
                            "[DISCOVERY] Trying next resolved "
                            "IPv4 address..."
                        )
                        continue

                    raise RuntimeError(
                        f"Nmap service scan failed for "
                        f"{target}: {exc}"
                    ) from exc

                if not isinstance(nmap_result, dict):

                    if len(resolved_ips) > 1:
                        print(
                            f"[DISCOVERY] Nmap returned an invalid "
                            f"result for {resolved_ip}."
                        )
                        print(
                            "[DISCOVERY] Trying next resolved "
                            "IPv4 address..."
                        )
                        continue

                    raise RuntimeError(
                        f"Nmap scanner returned an invalid result "
                        f"for {target}: "
                        f"{type(nmap_result).__name__}"
                    )

                ports = nmap_result.get("ports") or []

                host_status = str(
                    nmap_result.get(
                        "host_status",
                        "unknown",
                    )
                ).lower()

                print(
                    f"[DISCOVERY] {target} ({resolved_ip}): "
                    f"status={host_status}, "
                    f"{len(ports)} ports detected"
                )

                print(
                    f"[DISCOVERY] Ports: {ports}"
                )

                # A successful live result.
                if host_status in {"up", "unknown"} or ports:

                    devices.append(
                        {
                            "ip_address": resolved_ip,
                            "source": target,
                            "scan_mode": "live",
                            "discovered": True,
                            "host_status": host_status,
                            "ports": ports,
                        }
                    )

                    found_working_host = True
                    break

                print(
                    f"[DISCOVERY] {resolved_ip}: "
                    f"host is not live."
                )

                if len(resolved_ips) > 1:
                    print(
                        "[DISCOVERY] Trying next resolved "
                        "IPv4 address..."
                    )

            if not found_working_host:
                print(
                    f"[DISCOVERY] {target}: "
                    f"none of the resolved IPv4 addresses "
                    f"responded to the live scan."
                )

            continue

        # CIDR NETWORK TARGET
        try:
            network = ip_network(
                target,
                strict=False,
            )
        except ValueError as exc:
            raise ValueError(
                f"Invalid CIDR network: {target}"
            ) from exc

        print(
            f"[DISCOVERY] Network scan: {target}"
        )

        try:
            proc = subprocess.run(
                [
                    nmap_bin,
                    "-sn",
                    target,
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"Nmap host discovery timed out "
                f"for {target}."
            ) from exc
        except OSError as exc:
            raise RuntimeError(
                f"Unable to execute Nmap for "
                f"{target}: {exc}"
            ) from exc

        if proc.returncode != 0:
            stderr = (
                proc.stderr.strip()
                if proc.stderr
                else "No Nmap error message."
            )
            raise RuntimeError(
                f"Nmap host discovery failed for "
                f"{target}: {stderr}"
            )

        hosts_found = _parse_nmap_hosts(
            proc.stdout
        )

        print(
            f"[DISCOVERY] Active hosts found: "
            f"{hosts_found}"
        )

        for host in hosts_found:

            print(
                f"[DISCOVERY] Running service scan "
                f"against {host}"
            )

            try:
                nmap_result = scan_host(host)
            except Exception as exc:
                raise RuntimeError(
                    f"Nmap service scan failed for "
                    f"{host}: {exc}"
                ) from exc

            if not isinstance(nmap_result, dict):
                raise RuntimeError(
                    f"Nmap scanner returned an invalid "
                    f"result for {host}."
                )

            ports = nmap_result.get("ports") or []

            host_status = str(
                nmap_result.get(
                    "host_status",
                    "unknown",
                )
            ).lower()

            if host_status not in {"up", "unknown"} and not ports:
                print(
                    f"[DISCOVERY] {host}: "
                    f"no live host after service scan; "
                    f"skipping."
                )
                continue

            devices.append(
                {
                    "ip_address": host,
                    "source": target,
                    "scan_mode": "live",
                    "discovered": True,
                    "host_status": host_status,
                    "ports": ports,
                }
            )

    print("\n========================================")
    print(
        f"[DISCOVERY] LIVE DEVICES: {len(devices)}"
    )
    print("========================================")

    for device in devices:
        print(
            f"[DISCOVERY] "
            f"{device.get('ip_address')} -> "
            f"{len(device.get('ports', []))} ports"
        )

    print()

    return devices


def _parse_nmap_hosts(output: str) -> List[str]:
    """
    Extract IP addresses from Nmap -sn output.

    Handles normal output such as:
        Nmap scan report for 192.168.1.10

    and:
        Nmap scan report for hostname (192.168.1.10)
    """

    hosts: List[str] = []

    if not output:
        return hosts

    for raw_line in output.splitlines():

        line = raw_line.strip()

        if not line.startswith(
            "Nmap scan report for"
        ):
            continue

        value = line[
            len("Nmap scan report for"):
        ].strip()

        if "(" in value and ")" in value:
            candidate = (
                value.split("(")[-1]
                .split(")")[0]
                .strip()
            )
        else:
            candidate = (
                value.split()[0]
                .strip()
            )

        try:
            ip_address(candidate)
        except ValueError:
            continue

        if candidate not in hosts:
            hosts.append(candidate)

    return hosts


def _build_device(
    ip_text: str,
    source: str,
) -> Dict:
    """
    Build a simulated device record.
    """

    try:
        ip_address(ip_text)
    except ValueError as exc:
        raise ValueError(
            f"Invalid IP address or CIDR entry: "
            f"{ip_text}"
        ) from exc

    return {
        "ip_address": ip_text,
        "source": source,
        "scan_mode": "simulated",
        "discovered": True,
    }


if __name__ == "__main__":
    print(
        discover_devices(
            ["127.0.0.1"],
            mode="live",
        )
    )
