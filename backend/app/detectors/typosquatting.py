# SupplyGraph - Typosquatting Detector
from app.models.core import PURL, EvidenceItem, EvidenceClassification, EvidenceSource, FindingType
from Levenshtein import ratio
import uuid
import datetime
from typing import Optional

class TyposquattingDetector:
    def __init__(self):
        self.popular_packages = [
            "requests", "flask", "numpy", "lodash", "express", "react"
        ]

    def detect(self, purl: PURL) -> Optional[EvidenceItem]:
        if not purl.name:
            return None
        
        target_name = purl.name.lower()
        
        best_match = None
        max_ratio = 0.0
        
        for package in self.popular_packages:
            similarity = ratio(target_name, package)
            if similarity > max_ratio:
                max_ratio = similarity
                best_match = package
                
        if 0.8 <= max_ratio < 1.0:
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
