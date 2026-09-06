from __future__ import annotations

from typing import Dict, List, Optional, Sequence
from urllib.parse import unquote


# ---------------------------------------------------------------------------
# Conservative CVE knowledge base
# ---------------------------------------------------------------------------
# A CVE is returned only when the observed product/version is sufficient to
# support the match.  Generic service presence (for example, "ftp exists") is
# deliberately NOT treated as proof of a CVE.
#
# This prevents a service finding from being mislabeled as a CVE and keeps the
# distinction clear:
#   service finding = observed exposure / configuration weakness
#   CVE match      = observed software + affected version evidence
# ---------------------------------------------------------------------------

_CVE_DATABASE: List[Dict] = [
    {
        "cve_id": "CVE-2007-4915",
        "title": "Boa Webserver 0.93.15 stack-write vulnerability",
        "description": (
            "The Intersil isl3893 extensions for Boa 0.93.15 are vulnerable "
            "to a stack-write issue that can allow a remote attacker to change "
            "the administrator password through a crafted HTTP Basic Authentication request."
        ),
        "cvss_score": 10.0,
        "severity": "critical",
        "exploitability": "network",
        "product_aliases": ["boa", "boa httpd", "boa webserver"],
        "affected_versions": ["0.93.15"],
        "affected_version_ranges": [],
        "affected_services": ["http", "https"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2007-4915"],
    },
    {
        "cve_id": "CVE-2017-14491",
        "title": "dnsmasq heap buffer overflow",
        "description": (
            "dnsmasq versions before 2.78 contain a heap-based buffer overflow "
            "that can allow denial of service or arbitrary code execution through "
            "a crafted DNS response."
        ),
        "cvss_score": 9.8,
        "severity": "critical",
        "exploitability": "network",
        "product_aliases": ["dnsmasq", "gnu dnsmasq"],
        "affected_versions": [],
        "affected_version_ranges": [{"min": None, "max": "2.77"}],
        "affected_services": ["domain"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-14491"],
    },
    {
        "cve_id": "CVE-2023-40303",
        "title": "GNU inetutils privilege escalation",
        "description": (
            "GNU inetutils before 2.5 may allow privilege escalation because of "
            "unchecked return values in set*id() calls used by ftpd and other "
            "inetutils components."
        ),
        "cvss_score": 7.8,
        "severity": "high",
        "exploitability": "local",
        "product_aliases": ["inetutils", "gnu inetutils", "gnu inetutils ftpd"],
        "affected_versions": [],
        "affected_version_ranges": [{"min": None, "max": "2.4"}],
        "affected_services": ["ftp"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-40303"],
    },
    {
        "cve_id": "CVE-2026-21968",
        "title": "MySQL Server Optimizer denial of service",
        "description": (
            "A vulnerability in the MySQL Server Optimizer affects MySQL 8.0.0 "
            "through 8.0.44, 8.4.0 through 8.4.7, and 9.0.0 through 9.5.0."
        ),
        "cvss_score": 6.5,
        "severity": "medium",
        "exploitability": "network",
        "product_aliases": ["mysql", "mysql server", "oracle mysql"],
        "affected_versions": [],
        "affected_version_ranges": [
            {"min": "8.0.0", "max": "8.0.44"},
            {"min": "8.4.0", "max": "8.4.7"},
            {"min": "9.0.0", "max": "9.5.0"},
        ],
        "affected_services": ["mysql"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-21968"],
    },
    {
        "cve_id": "CVE-2026-21964",
        "title": "MySQL Server Thread Pooling denial of service",
        "description": (
            "A vulnerability in MySQL Server Thread Pooling affects MySQL 8.0.0 "
            "through 8.0.44, 8.4.0 through 8.4.7, and 9.0.0 through 9.5.0."
        ),
        "cvss_score": 4.9,
        "severity": "medium",
        "exploitability": "network",
        "product_aliases": ["mysql", "mysql server", "oracle mysql"],
        "affected_versions": [],
        "affected_version_ranges": [
            {"min": "8.0.0", "max": "8.0.44"},
            {"min": "8.4.0", "max": "8.4.7"},
            {"min": "9.0.0", "max": "9.5.0"},
        ],
        "affected_services": ["mysql"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-21964"],
    },
]


def match_cves(
    vendor: str,
    firmware_version: str,
    services: List[str],
    *,
    product: str = "",
    version: str = "",
    cpe: str = "",
) -> List[Dict]:
    """Return only CVEs supported by concrete product/version evidence.

    The first three positional parameters are retained for compatibility with
    the existing scanner.  Product-level matching should pass ``product`` and
    ``version`` explicitly.  No CVE is produced from service presence alone.

    CPE matching is an additional evidence source when Nmap provides a CPE.
    Only application CPEs are considered here. Operating-system and hardware
    CPEs are ignored for application CVE matching.
    """
    observed_product = _normalize_product(product or vendor)
    observed_version = str(version or firmware_version or "").strip()
    services_lower = {str(s).strip().lower() for s in services or []}

    parsed_cpe = _parse_cpe(cpe)

    if not observed_product and not parsed_cpe:
        return []

    matched: Dict[str, Dict] = {}

    for cve in _CVE_DATABASE:
        cpe_match = _cpe_matches(cve, parsed_cpe)

        product_version_match = False

        if (
            observed_product
            and _known_version(observed_version)
        ):
            product_version_match = (
                _product_matches(
                    observed_product,
                    cve.get("product_aliases", []),
                )
                and _version_matches(
                    observed_version,
                    cve.get("affected_versions", []),
                    cve.get("affected_version_ranges", []),
                )
            )

        if not cpe_match and not product_version_match:
            continue

        affected_services = {
            str(s).lower() for s in cve.get("affected_services", [])
        }

        if affected_services and not (affected_services & services_lower):
            continue

        if cpe_match:
            match_source = "cpe"
            matched_by = f"CPE {cpe}"
        else:
            match_source = "product_version"
            matched_by = (
                f"product {product or vendor} + version {observed_version}"
            )

        matched[cve["cve_id"]] = {
            "cve_id": cve["cve_id"],
            "title": cve["title"],
            "description": cve["description"],
            "cvss_score": cve["cvss_score"],
            "severity": cve["severity"],
            "exploitability": cve["exploitability"],
            "affected_versions": list(cve.get("affected_versions", [])),
            "affected_version_range": (
                cve.get("affected_version_ranges", [None])[0]
                if cve.get("affected_version_ranges")
                else None
            ),
            "affected_services": list(cve.get("affected_services", [])),
            "matched_by": matched_by,
            "match_source": match_source,
            "observed_cpe": cpe,
            "references": list(cve.get("references", [])),
        }

    return sorted(
        matched.values(),
        key=lambda c: c["cvss_score"],
        reverse=True,
    )


def get_cve_summary(cve_matches: List[Dict]) -> Dict:
    """Summarise CVE matches by severity."""
    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for cve in cve_matches or []:
        severity = str(cve.get("severity", "")).lower()

        if severity in breakdown:
            breakdown[severity] += 1

    return {
        "total": len(cve_matches or []),
        "breakdown": breakdown,
        "top_cvss": cve_matches[0]["cvss_score"] if cve_matches else 0.0,
        "top_cve": cve_matches[0]["cve_id"] if cve_matches else None,
    }


def get_cve_ids(cve_matches: List[Dict]) -> List[str]:
    """Return only CVE identifiers."""
    return [c["cve_id"] for c in cve_matches or []]


def _normalize_product(product: str) -> str:
    value = str(product or "").lower().strip()
    value = value.replace("/", " ")
    value = " ".join(value.split())
    return value


def _product_matches(observed: str, aliases: Sequence[str]) -> bool:
    for alias in aliases:
        candidate = _normalize_product(alias)

        if observed == candidate:
            return True

        # Nmap often adds a suffix such as "Server" or "FTPd".
        if observed.startswith(candidate + " "):
            return True

    return False


def _parse_cpe(cpe: str) -> Optional[Dict[str, str]]:
    """Parse CPE 2.2 and CPE 2.3 strings.

    Examples:
        cpe:/a:mysql:mysql:8.0.44
        cpe:2.3:a:mysql:mysql:8.0.44:*:*:*:*:*:*:*
    """
    value = str(cpe or "").strip()

    if not value:
        return None

    # CPE 2.3
    if value.startswith("cpe:2.3:"):
        parts = value.split(":")

        if len(parts) < 6:
            return None

        return {
            "part": _decode_cpe_value(parts[2]),
            "vendor": _decode_cpe_value(parts[3]),
            "product": _decode_cpe_value(parts[4]),
            "version": _decode_cpe_value(parts[5]),
        }

    # CPE 2.2
    if value.startswith("cpe:/"):
        parts = value[5:].split(":")

        if len(parts) < 3:
            return None

        return {
            "part": _decode_cpe_value(parts[0]),
            "vendor": _decode_cpe_value(parts[1]),
            "product": _decode_cpe_value(parts[2]),
            "version": (
                _decode_cpe_value(parts[3])
                if len(parts) > 3
                else ""
            ),
        }

    return None


def _decode_cpe_value(value: str) -> str:
    """Decode a CPE component."""
    value = str(value or "")

    if value in {"*", "-"}:
        return ""

    return unquote(value).strip()


def _cpe_matches(
    cve: Dict,
    parsed_cpe: Optional[Dict[str, str]],
) -> bool:
    """Check whether an application CPE matches a CVE."""
    if not parsed_cpe:
        return False

    # CPE parts:
    #   a = application
    #   o = operating system
    #   h = hardware
    #
    # This matcher handles application CVEs only.
    if parsed_cpe.get("part", "").lower() != "a":
        return False

    cpe_vendor = parsed_cpe.get("vendor", "").lower().strip()
    cpe_product = parsed_cpe.get("product", "").lower().strip()
    cpe_version = parsed_cpe.get("version", "").strip()

    if not cpe_vendor or not cpe_product:
        return False

    if not _known_version(cpe_version):
        return False

    aliases = [
        _normalize_product(alias)
        for alias in cve.get("product_aliases", [])
    ]

    for alias in aliases:
        if not alias:
            continue

        alias_parts = alias.split()

        # Single-word aliases such as:
        # mysql, boa, dnsmasq
        #
        # For these, accept the same vendor/product name.
        if len(alias_parts) == 1:
            alias_vendor = alias_parts[0]
            alias_product = alias_parts[0]

            if (
                cpe_vendor == alias_vendor
                and cpe_product == alias_product
            ):
                return _version_matches(
                    cpe_version,
                    cve.get("affected_versions", []),
                    cve.get("affected_version_ranges", []),
                )

            continue

        # Multi-word aliases such as:
        # oracle mysql
        # gnu inetutils
        # boa webserver
        #
        # Treat the first word as vendor and the last word
        # as the product name.
        alias_vendor = alias_parts[0]
        alias_product = alias_parts[-1]

        vendor_matches = cpe_vendor == alias_vendor

        product_matches = (
            cpe_product == alias_product
            or cpe_product.startswith(alias_product + " ")
        )

        if vendor_matches and product_matches:
            return _version_matches(
                cpe_version,
                cve.get("affected_versions", []),
                cve.get("affected_version_ranges", []),
            )

    return False


def _known_version(version: str) -> bool:
    return bool(version) and version.lower() not in {
        "unknown", "none", "n/a", "na", "0", "-"
    }


def _version_tuple(version: str) -> tuple[int, ...]:
    parts = []

    for token in str(version).replace("-", ".").split("."):
        digits = "".join(ch for ch in token if ch.isdigit())

        if digits:
            parts.append(int(digits))

    return tuple(parts) if parts else (0,)


def _version_matches(
    version: str,
    exact_versions: Sequence[str],
    ranges: Sequence[Dict],
) -> bool:
    if version in exact_versions:
        return True

    current = _version_tuple(version)

    if current == (0,):
        return False

    for item in ranges:
        minimum = item.get("min")
        maximum = item.get("max")

        if minimum and current < _version_tuple(minimum):
            continue

        if maximum and current > _version_tuple(maximum):
            continue

        return True

    return False