from app.models.core import VulnerabilityModel, PURL, Severity
from app.core.config import get_settings
from typing import List, Dict, Any, Optional
import httpx
import json
import os
import aiofiles
from pathlib import Path
from datetime import datetime

class OSVClient:
    def __init__(self):
        self.settings = get_settings()
        self.cache_dir = Path(self.settings.osv_cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.batch_url = "https://api.osv.dev/v1/querybatch"
        self.vuln_url = "https://api.osv.dev/v1/vulns/{}"

    async def query_batch(self, components: List[PURL]) -> Dict[str, List[VulnerabilityModel]]:
        results: Dict[str, List[VulnerabilityModel]] = {}
        if not components:
            return results
            
        queries = []
        for c in components:
            # Map PURL ecosystems to exact OSV API schema ecosystems
            eco_map = {
                "npm": "npm",
                "pypi": "PyPI",
                "maven": "Maven",
                "golang": "Go",
                "cargo": "crates.io",
                "nuget": "NuGet"
            }
            ecosystem_str = eco_map.get(c.ecosystem.value, c.ecosystem.value)
            
            package_name = f"{c.namespace}/{c.name}" if c.namespace else c.name
            
            q = {
                "package": {"name": package_name, "ecosystem": ecosystem_str}
            }
            if c.version:
                q["version"] = c.version
            queries.append(q)
            
        payload = {
            "queries": queries
        }
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(self.batch_url, json=payload, timeout=30.0)
                response.raise_for_status()
                data = response.json()
                
                batch_results = data.get("results", [])
                for i, result in enumerate(batch_results):
                    purl_str = components[i].canonical
                    vulns_data = result.get("vulns", [])
                    vuln_models = []
                    
                    for v in vulns_data:
                        vuln_id = v.get("id")
                        modified = v.get("modified")
                        if not vuln_id:
                            continue
                            
                        full_vuln = await self._get_cached_or_fetch(client, vuln_id, modified)
                        if full_vuln:
                            vuln_models.append(self._parse_vuln(full_vuln))
                            
                    if vuln_models:
                        results[purl_str] = vuln_models
            except Exception as e:
                print(f"OSV Client error: {e}")
                pass
                
        return results

    async def _get_cached_or_fetch(self, client: httpx.AsyncClient, vuln_id: str, modified: Optional[str]) -> Optional[Dict[str, Any]]:
        cache_path = self.cache_dir / f"{vuln_id}.json"
        
        if cache_path.exists():
            try:
                async with aiofiles.open(cache_path, "r") as f:
                    content = await f.read()
                    cached_data = json.loads(content)
                    if not modified or cached_data.get("modified") == modified:
                        return cached_data
            except (json.JSONDecodeError, OSError):
                pass
                
        try:
            url = self.vuln_url.format(vuln_id)
            response = await client.get(url, timeout=15.0)
            response.raise_for_status()
            full_vuln = response.json()
            
            async with aiofiles.open(cache_path, "w") as f:
                await f.write(json.dumps(full_vuln))
                
            return full_vuln
        except Exception:
            return None
            
    def _parse_vuln(self, data: Dict[str, Any]) -> VulnerabilityModel:
        cvss_score = None
        cvss_vector = None
        severity_enum = Severity.UNKNOWN
        
        severities = data.get("severity", [])
        for sev in severities:
            if sev.get("type") == "CVSS_V3":
                cvss_vector = sev.get("score")
                
        published_str = data.get("published")
        modified_str = data.get("modified")
        
        def parse_date(d: Optional[str]) -> Optional[datetime]:
            if not d:
                return None
            try:
                return datetime.fromisoformat(d.replace("Z", "+00:00"))
            except ValueError:
                return None
                
        published_at = parse_date(published_str)
        modified_at = parse_date(modified_str)
        
        affected_ecosystems = []
        fixed_versions = {}
        cwe_ids = []
        
        for affected in data.get("affected", []):
            eco = affected.get("package", {}).get("ecosystem")
            if eco and eco not in affected_ecosystems:
                affected_ecosystems.append(eco)
                
            ranges = affected.get("ranges", [])
            for r in ranges:
                for event in r.get("events", []):
                    if "fixed" in event:
                        fixed_versions[eco or "unknown"] = event["fixed"]
                        
        aliases = data.get("aliases", [])
        for alias in aliases:
            if alias.startswith("CWE-"):
                cwe_ids.append(alias)
                
        return VulnerabilityModel(
            osv_id=data.get("id", ""),
            aliases=aliases,
            summary=data.get("summary", "No summary provided"),
            details=data.get("details"),
            severity=severity_enum,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwe_ids=cwe_ids,
            affected_ecosystems=affected_ecosystems,
            fixed_versions=fixed_versions,
            references=data.get("references", []),
            published_at=published_at,
            modified_at=modified_at,
            osv_modified=modified_str
        )
