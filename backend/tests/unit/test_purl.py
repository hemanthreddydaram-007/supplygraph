"""
Unit tests for PURL normalization.
Tests canonical PURL construction and parsing.
"""

import pytest
from app.models.core import PURL, Ecosystem


class TestPURLCanonical:

    def test_pypi_purl_canonical(self):
        purl = PURL(ecosystem=Ecosystem.PYPI, name="requests", version="2.31.0")
        assert purl.canonical == "pkg:pypi/requests@2.31.0"

    def test_npm_purl_canonical(self):
        purl = PURL(ecosystem=Ecosystem.NPM, name="lodash", version="4.17.20")
        assert purl.canonical == "pkg:npm/lodash@4.17.20"

    def test_npm_purl_with_namespace(self):
        purl = PURL(ecosystem=Ecosystem.NPM, name="cli", namespace="aws-cdk", version="2.0.0")
        assert purl.canonical == "pkg:npm/aws-cdk/cli@2.0.0"

    def test_purl_without_version(self):
        purl = PURL(ecosystem=Ecosystem.PYPI, name="requests")
        assert purl.canonical == "pkg:pypi/requests"
        assert "@" not in purl.canonical

    def test_purl_ecosystem_prefix(self):
        purl = PURL(ecosystem=Ecosystem.MAVEN, name="spring-core", namespace="org.springframework", version="6.0.0")
        assert purl.canonical.startswith("pkg:maven/")


class TestPURLFromString:

    def test_parse_pypi_purl(self):
        purl = PURL.from_string("pkg:pypi/requests@2.31.0")
        assert purl.ecosystem == Ecosystem.PYPI
        assert purl.name == "requests"
        assert purl.version == "2.31.0"

    def test_parse_npm_purl(self):
        purl = PURL.from_string("pkg:npm/lodash@4.17.20")
        assert purl.ecosystem == Ecosystem.NPM
        assert purl.name == "lodash"
        assert purl.version == "4.17.20"

    def test_parse_purl_without_version(self):
        purl = PURL.from_string("pkg:pypi/flask")
        assert purl.name == "flask"
        assert purl.version is None

    def test_parse_purl_with_namespace(self):
        purl = PURL.from_string("pkg:npm/aws-cdk/cli@2.0.0")
        assert purl.namespace == "aws-cdk"
        assert purl.name == "cli"

    def test_invalid_purl_raises_value_error(self):
        with pytest.raises(ValueError):
            PURL.from_string("not-a-valid-purl")

    def test_roundtrip_pypi(self):
        """Parse a PURL string and re-generate canonical — must match."""
        original = "pkg:pypi/requests@2.31.0"
        purl = PURL.from_string(original)
        assert purl.canonical == original

    def test_roundtrip_npm(self):
        original = "pkg:npm/lodash@4.17.20"
        purl = PURL.from_string(original)
        assert purl.canonical == original


class TestPURLFrozen:

    def test_purl_is_immutable(self):
        purl = PURL(ecosystem=Ecosystem.PYPI, name="requests", version="2.31.0")
        with pytest.raises(Exception):
            purl.name = "modified"  # type: ignore[misc]
