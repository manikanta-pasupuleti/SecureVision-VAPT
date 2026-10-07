from scanner.discovery import discover_devices
from scanner.fingerprint import fingerprint_device


def test_simulated_scan_is_deterministic_and_network_free():
    first = discover_devices(["192.168.1.50"], mode="simulated")
    second = discover_devices(["192.168.1.50"], mode="simulated")

    assert first == second
    assert first[0]["scan_mode"] == "simulated"

    device = fingerprint_device(first[0])
    assert device["fingerprint_source"] == "simulation"
    assert device["device_type"] == "Surveillance Device"
    assert device["vendor"] in {"Hikvision", "Dahua", "Axis", "Uniview"}
    assert device["services"]
