# SupplyGraph - Comprehensive Tests for Dependency Deduplication, OSV Alias Merging, and Fix Resolution
import pytest
from app.services.lockfile_parser import LockfileParser, normalize_pypi_name, _dedupe_components
from app.services.osv_client import OSVClient, merge_aliased_records, resolve_best_fixed_version
from app.models.core import SBOMComponent, Ecosystem, PURL


def test_normalize_pypi_name():
    assert normalize_pypi_name("Cryptography") == "cryptography"
    assert normalize_pypi_name("urllib3.extra_pkg") == "urllib3-extra-pkg"
    assert normalize_pypi_name("torch_geometric") == "torch-geometric"
    assert normalize_pypi_name("osv-dev") == "osv-dev"


def test_pypi_single_version_resolution_dedupe_components():
    """
    Python pip environments only allow a single installed version of a package.
    When multiple version bounds are present, unifies to the highest required version.
    """
    comp1 = SBOMComponent(
        bom_ref="pkg:pypi/cryptography@42.0.5",
        name="cryptography",
        version="42.0.5",
        ecosystem=Ecosystem.PYPI,
        purl="pkg:pypi/cryptography@42.0.5",
        is_direct=True,
        depth=1
    )
    comp2 = SBOMComponent(
        bom_ref="pkg:pypi/cryptography@44.0.1",
        name="cryptography",
        version="44.0.1",
        ecosystem=Ecosystem.PYPI,
        purl="pkg:pypi/cryptography@44.0.1",
        is_direct=False,
        depth=2
    )

    deduped = _dedupe_components([comp1, comp2])
    assert len(deduped) == 1
    # Resolved version should be 44.0.1 (highest required minimum bound)
    assert deduped[0].version == "44.0.1"
    # Should preserve direct=True because comp1 was direct
    assert deduped[0].is_direct is True
    # Should preserve depth=1
    assert deduped[0].depth == 1


def test_requirements_txt_transitive_dedupes_cryptography_and_tornado():
    """
    Tests parsing a requirements.txt file where transitive dependencies
    would otherwise pull in duplicate older versions of packages (e.g. tornado 6.4 and cryptography 42.0.5).
    Verifies that only a single version node is preserved (the highest required version).
    """
    parser = LockfileParser()
    req_content = """
    fastapi==0.110.0
    streamlit==1.32.0
    pyjwt==2.8.0
    cryptography>=44.0.1
    tornado>=6.5.9
    """
    components = parser._parse_requirements_txt(req_content)

    # Verify no duplicate nodes exist for cryptography or tornado
    crypto_nodes = [c for c in components if normalize_pypi_name(c.name) == "cryptography"]
    tornado_nodes = [c for c in components if normalize_pypi_name(c.name) == "tornado"]

    assert len(crypto_nodes) == 1
    assert crypto_nodes[0].version == "44.0.1"

    assert len(tornado_nodes) == 1
    assert tornado_nodes[0].version == "6.5.9"


def test_merge_aliased_records_ghsa_pysec_cve():
    """
    Tests that aliased OSV records (GHSA-* and PYSEC-*) sharing CVE identifiers
    are merged into a single record preferring GHSA-* as primary display ID,
    preserving non-empty summary and unifying all fixed versions.
    """
    records = [
        {
            "id": "PYSEC-2026-1994",
            "aliases": ["CVE-2025-66471", "GHSA-2xpw-w6gg-jr37"],
            "summary": "",
            "details": "urllib3 streaming API vulnerability details from PYSEC.",
            "affected": [
                {
                    "package": {"name": "urllib3", "ecosystem": "PyPI"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.6.0"}]}]
                }
            ]
        },
        {
            "id": "GHSA-2xpw-w6gg-jr37",
            "aliases": ["CVE-2025-66471", "PYSEC-2026-1994"],
            "summary": "urllib3 streaming API improperly handles highly compressed data",
            "details": "Comprehensive details from GitHub Security Advisory.",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
            "database_specific": {"severity": "HIGH"},
            "affected": [
                {
                    "package": {"name": "urllib3", "ecosystem": "PyPI"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.6.0"}]}]
                }
            ]
        }
    ]

    merged = merge_aliased_records(records, target_pkg_name="urllib3")
    assert len(merged) == 1
    m = merged[0]

    # Primary ID should be GHSA-*
    assert m["id"] == "GHSA-2xpw-w6gg-jr37"
    # Aliases should include CVE and PYSEC
    assert "CVE-2025-66471" in m["aliases"]
    assert "PYSEC-2026-1994" in m["aliases"]
    # Summary should come from GHSA
    assert m["summary"] == "urllib3 streaming API improperly handles highly compressed data"
    # Fixed version should be 2.6.0
    fixes = []
    for aff in m.get("affected", []):
        for rg in aff.get("ranges", []):
            for ev in rg.get("events", []):
                if "fixed" in ev and ev["fixed"]:
                    fixes.append(str(ev["fixed"]))
    assert "2.6.0" in fixes


def test_resolve_best_fixed_version_strict_greater():
    """
    Ensure resolve_best_fixed_version requires fixed > installed_version
    and correctly resolves multi-branch candidate fixes.
    """
    # urllib3 2.0.7 with fixes in 1.26.19 (backport) and 2.2.2 (same major upgrade)
    fixes = ["1.26.19", "2.2.2"]
    best = resolve_best_fixed_version("2.0.7", fixes)
    assert best == "2.2.2"

    # certifi 2024.2.2 with commit hash and valid semver fixes
    certifi_fixes = ["2024.7.4", "2026.10.18", "bd8153872e9c6fc98f4023df9c2deaffea2fa463"]
    best_certifi = resolve_best_fixed_version("2024.2.2", certifi_fixes)
    assert best_certifi == "2024.7.4"

    # If candidate fix is identical to installed version, it must not be recommended
    assert resolve_best_fixed_version("2.0.7", ["2.0.7"]) is None
