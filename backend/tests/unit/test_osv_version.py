# SupplyGraph - Tests for SemVer Fixed Version Resolution
import pytest
from app.services.osv_client import resolve_best_fixed_version

def test_resolve_same_major_lowest_upgrade():
    # Installed 1.2.0, available fixes: 1.1.0 (old), 1.2.3, 1.4.0, 2.0.0
    # Should pick 1.2.3 (least disruptive patch in same major)
    fixed = resolve_best_fixed_version("1.2.0", ["1.1.0", "1.4.0", "1.2.3", "2.0.0"])
    assert fixed == "1.2.3"

def test_resolve_higher_major_when_no_same_major():
    # Installed 1.5.0, fixes only available in major 2 and 3: 2.0.1, 3.0.0
    # Should pick 2.0.1 (lowest in next major)
    fixed = resolve_best_fixed_version("1.5.0", ["3.0.0", "2.0.1"])
    assert fixed == "2.0.1"

def test_resolve_never_downgrades():
    # Installed 2.5.0, but OSV candidate fix is backport for older 1.x branch: 1.8.2
    # Should NOT downgrade to 1.8.2; should recommend next major >=3.0.0
    fixed = resolve_best_fixed_version("2.5.0", ["1.8.2"])
    assert fixed == ">=3.0.0"

def test_resolve_empty_or_none():
    assert resolve_best_fixed_version("1.0.0", []) is None
    assert resolve_best_fixed_version(None, ["1.2.0"]) == "1.2.0"
