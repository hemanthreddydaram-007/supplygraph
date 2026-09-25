import pytest
from app.detectors.typosquatting import TyposquattingDetector
from app.models.core import PURL, Ecosystem

class TestTyposquattingDetector:
    def test_exact_match_is_not_typosquatting(self):
        detector = TyposquattingDetector()
        purl = PURL(ecosystem=Ecosystem.PYPI, name="requests")
        evidence = detector.detect(purl)
        # Exact match (1.0) should not trigger a typosquatting alert
        assert evidence is None

    def test_distant_match_is_not_typosquatting(self):
        detector = TyposquattingDetector()
        purl = PURL(ecosystem=Ecosystem.PYPI, name="something-completely-unrelated")
        evidence = detector.detect(purl)
        # Low similarity score should not trigger
        assert evidence is None

    def test_transposition_is_caught(self):
        detector = TyposquattingDetector()
        # requests -> reqeusts
        purl = PURL(ecosystem=Ecosystem.PYPI, name="reqeusts")
        evidence = detector.detect(purl)
        assert evidence is not None
        assert "requests" in evidence.description
        assert "reqeusts" in evidence.description

    def test_character_substitution(self):
        detector = TyposquattingDetector()
        # react -> reakt
        purl = PURL(ecosystem=Ecosystem.NPM, name="reakt")
        evidence = detector.detect(purl)
        assert evidence is not None
        assert "react" in evidence.description
        
    def test_omission(self):
        detector = TyposquattingDetector()
        # express -> expres
        purl = PURL(ecosystem=Ecosystem.NPM, name="expres")
        evidence = detector.detect(purl)
        assert evidence is not None
        assert "express" in evidence.description
