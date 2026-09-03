from scanner.cve_matcher import get_cve_ids, match_cves


def test_service_presence_alone_does_not_create_cve():
    assert match_cves("Unknown", "Unknown", ["ftp", "http"]) == []


def test_boa_09315_exact_product_version_matches_verified_cve():
    matches = match_cves(
        "Unknown",
        "Unknown",
        ["http"],
        product="Boa HTTPd",
        version="0.93.15",
    )
    assert "CVE-2007-4915" in get_cve_ids(matches)


def test_dnsmasq_245_matches_cve_2017_14491():
    matches = match_cves(
        "Unknown",
        "Unknown",
        ["domain"],
        product="dnsmasq",
        version="2.45",
    )
    assert "CVE-2017-14491" in get_cve_ids(matches)


def test_inetutils_141_matches_cve_2023_40303():
    matches = match_cves(
        "Unknown",
        "Unknown",
        ["ftp"],
        product="GNU Inetutils FTPd",
        version="1.4.1",
    )
    assert "CVE-2023-40303" in get_cve_ids(matches)


def test_mysql_8044_matches_both_2026_cves():
    matches = match_cves(
        "Unknown",
        "Unknown",
        ["mysql"],
        product="MySQL Server",
        version="8.0.44",
    )
    ids = get_cve_ids(matches)
    assert "CVE-2026-21968" in ids
    assert "CVE-2026-21964" in ids
