from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import List, Dict, Optional
import shutil
import subprocess

from scanner.nmap_scanner import scan_host


def discover_devices(
    targets: List[str],
    mode: str = "live",
) -> List[Dict]:
    """
    Discover devices from target IP addresses or CIDR networks.

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

        # ---------------------------------------------------------
        # DIRECT IP TARGET
        # ---------------------------------------------------------
        #
        # Example:
        #     127.0.0.1
        #
        # Do NOT run -sn first.
        # scan_host() already performs the actual Nmap service
        # detection that we need.
        #
        if "/" not in target:

            try:
                ip_address(target)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid IP address: {target}"
                ) from exc

            print(
                f"[DISCOVERY] Direct live scan: {target}"
            )

            try:

                nmap_result = scan_host(target)

            except Exception as exc:

                raise RuntimeError(
                    f"Nmap service scan failed for "
                    f"{target}: {exc}"
                ) from exc

            if not isinstance(nmap_result, dict):

                raise RuntimeError(
                    f"Nmap scanner returned an invalid result "
                    f"for {target}: "
                    f"{type(nmap_result).__name__}"
                )

            ports = nmap_result.get("ports") or []
            host_status = str(nmap_result.get("host_status", "unknown")).lower()

            print(
                f"[DISCOVERY] {target}: status={host_status}, "
                f"{len(ports)} ports detected"
            )
            print(f"[DISCOVERY] Ports: {ports}")

            if host_status not in {"up", "unknown"} and not ports:
                print(
                    f"[DISCOVERY] {target}: host is not live; "
                    "skipping it instead of creating a simulated device."
                )
                continue

            devices.append(
                {
                    "ip_address": target,
                    "source": target,
                    "scan_mode": "live",
                    "discovered": True,
                    "host_status": host_status,
                    "ports": ports,
                }
            )

            continue

        # ---------------------------------------------------------
        # CIDR TARGET
        # ---------------------------------------------------------
        #
        # Example:
        #     192.168.1.0/24
        #
        # First discover active hosts.
        # Then perform service/version detection.
        #
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
                f"Nmap host discovery timed out for {target}."
            ) from exc

        except OSError as exc:

            raise RuntimeError(
                f"Unable to execute Nmap for {target}: {exc}"
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
            host_status = str(nmap_result.get("host_status", "unknown")).lower()

            if host_status not in {"up", "unknown"} and not ports:
                print(
                    f"[DISCOVERY] {host}: no live host after service scan; skipping."
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

        # ---------------------------------------------------------
        # hostname (IP)
        # ---------------------------------------------------------
        if "(" in value and ")" in value:

            candidate = (
                value.split("(")[-1]
                .split(")")[0]
                .strip()
            )

        else:

            # -----------------------------------------------------
            # direct IP / hostname
            # -----------------------------------------------------
            candidate = value.split()[0].strip()

        try:

            ip_address(candidate)

        except ValueError:

            # Ignore hostname-only entries because the rest
            # of the scanner expects an IP address.
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