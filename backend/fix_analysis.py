import re

with open("app/services/analysis_service.py", "r") as f:
    content = f.read()

content = content.replace("impact=None,", "impact=compute_blast_radius(package_count=1, service_count=1, api_count=0, production_deployment_count=0),")
content = content.replace("confidence=None,", "confidence=compute_confidence([ConfidenceFactor(evidence_type=\"OSV_MATCH\", source=\"osv\", raw_weight=0.9, reliability=1.0)]),")

content = re.sub(r'factors = \[ConfidenceFactor\(.*?\)\].*?finding\.impact = compute_blast_radius\(.*?\)', '', content, flags=re.DOTALL)

with open("app/services/analysis_service.py", "w") as f:
    f.write(content)
