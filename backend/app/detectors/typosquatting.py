# SupplyGraph - Typosquatting Detector
from app.models.core import PURL, EvidenceItem, EvidenceClassification, EvidenceSource, FindingType, Ecosystem
from Levenshtein import ratio
import uuid
import datetime
from typing import Optional, Set, List

class TyposquattingDetector:
    # Explicit whitelist of popular legitimate libraries that must never be flagged
    WHITELIST: Set[str] = {
        "request", "requests", "express", "lodash", "chalk", "debug",
        "commander", "react", "next", "axios", "moment", "async", "jade",
        "pug", "ejs", "bcrypt", "jsonwebtoken", "mongoose", "sequelize",
        "fastapi", "pydantic", "uvicorn", "networkx", "pytest", "httpx",
        "urllib3", "six", "idna", "click", "flask", "django", "celery",
        "redis", "boto3", "dotenv", "cors", "body-parser", "cookie-parser",
        "morgan", "typescript", "tslib", "rxjs", "webpack", "babel",
        "eslint", "prettier", "jest", "mocha", "chai", "glob", "semver",
        "uuid", "yargs", "minimist", "mkdirp", "rimraf", "inquirer"
    }

    def __init__(self):
        # Ecosystem-specific popular targets
        self.popular_npm: List[str] = [
            "express", "lodash", "react", "axios", "chalk", "debug", "commander",
            "moment", "async", "bcrypt", "jsonwebtoken", "mongoose", "webpack",
            "typescript", "next", "body-parser", "dotenv"
        ]
        self.popular_pypi: List[str] = [
            "requests", "flask", "numpy", "pandas", "scipy", "django", "fastapi",
            "pydantic", "urllib3", "cryptography", "pytest", "boto3", "celery",
            "redis", "click", "pillow", "jinja2"
        ]

    def detect(self, purl: PURL) -> Optional[EvidenceItem]:
        if not purl.name:
            return None
        
        target_name = purl.name.lower()

        # 1. Whitelist check: legitimate libraries are never flagged as typosquats
        if target_name in self.WHITELIST:
            return None

        # 2. Select candidates based strictly on ecosystem
        if purl.ecosystem == Ecosystem.NPM:
            candidates = self.popular_npm
        elif purl.ecosystem == Ecosystem.PYPI:
            candidates = self.popular_pypi
        else:
            candidates = self.popular_npm + self.popular_pypi

        # Exact match check
        if target_name in candidates:
            return None
        
        best_match = None
        max_ratio = 0.0
        
        for package in candidates:
            similarity = ratio(target_name, package)
            if similarity > max_ratio:
                max_ratio = similarity
                best_match = package
                
        if 0.8 <= max_ratio < 1.0 and best_match:
            return EvidenceItem(
                id=str(uuid.uuid4()),
                source=EvidenceSource.TYPOSQUATTING,
                evidence_type="TYPOSQUATTING",
                classification=EvidenceClassification.HEURISTIC,
                description=f"Potential typosquatting: '{target_name}' is suspiciously similar to popular package '{best_match}' (similarity: {max_ratio:.2f})",
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                confidence_contribution=max_ratio,
                raw_data={
                    "target_package": target_name,
                    "similar_to": best_match,
                    "similarity_score": max_ratio
                }
            )
            
        return None
