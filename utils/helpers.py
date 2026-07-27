from __future__ import annotations

from ipaddress import ip_network


def normalize_target(target):
    return target.strip()


def parse_target_input(target_spec):
    targets = []
    for chunk in target_spec.replace("\n", ",").split(","):
        item = chunk.strip()
        if not item:
            continue
        if "/" in item:
            ip_network(item, strict=False)
        targets.append(item)

    if not targets:
        raise ValueError("No valid targets were provided.")

    return targets
