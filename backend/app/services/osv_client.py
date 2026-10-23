# SupplyGraph - OSV Intelligence Engine v3.0
# Batch querying with persistent cache and SemVer-aware fixed version resolution
from app.models.core import VulnerabilityModel, PURL, Severity
from app.core.config import get_settings
from typing import List, Dict, Any, Optional
import httpx
import json
import os
import aiofiles
from pathlib import Path
from datetime import datetime


def resolve_best_fixed_version(installed_version: Optional[str], candidate_fixes: List[str]) -> Optional[str]:
    """
    Selects the least disruptive patched SemVer fix without ever downgrading major versions.
    1. Prefer lowest patched version within the same major version >= installed_version.
    2. Otherwise, prefer lowest patched version in higher major versions.
    3. Never recommend a major downgrade.
    """
    if not candidate_fixes:
        return None

    clean_candidates = []
    for c in candidate_fixes:
        if isinstance(c, list):
            clean_candidates.extend(str(item).strip() for item in c if str(item).strip())
        elif isinstance(c, str) and c.strip():
            clean_candidates.append(c.strip())

    if not clean_candidates:
        return None

    if not installed_version:
        return clean_candidates[0]

    # Clean installed version
    inst_clean = installed_version.strip().lstrip("v^~>=<")

    try:
        from packaging.version import parse as parse_version
        inst_v = parse_version(inst_clean)
    except Exception:
        return clean_candidates[0]

    valid_fixes = []
    for cand in clean_candidates:
        try:
            cand_clean = cand.lstrip("v^~>=<")
            cand_v = parse_version(cand_clean)
            valid_fixes.append((cand_v, cand))
        except Exception:
            continue

    if not valid_fixes:
        return clean_candidates[0]

    inst_major = getattr(inst_v, "major", None)

    # 1. Candidate fixes with same major and >= installed_version
    same_major_upgrades = [
        (v, raw) for v, raw in valid_fixes
        if getattr(v, "major", None) == inst_major and v >= inst_v
    ]
    if same_major_upgrades:
        same_major_upgrades.sort(key=lambda x: x[0])
        return same_major_upgrades[0][1]

    # 2. Candidate fixes with higher major
    higher_major_upgrades = [
        (v, raw) for v, raw in valid_fixes
        if inst_major is not None and getattr(v, "major", 0) > inst_major
    ]
    if higher_major_upgrades:
        higher_major_upgrades.sort(key=lambda x: x[0])
        return higher_major_upgrades[0][1]

    # 3. If all fixes are strictly lower than installed (backports to older branches),
    # do NOT downgrade and do NOT fabricate non-existent versions! Return None so caller knows no fix exists.
    return None


def compute_cvss3_score(vector_str: str) -> Optional[float]:
    """Calculate CVSS v3.x base score from vector string."""
    try:
        clean = vector_str.replace("CVSS:3.1/", "").replace("CVSS:3.0/", "")
        parts = dict(p.split(":") for p in clean.split("/") if ":" in p)
        av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_map = {"L": 0.77, "H": 0.44}
        pr_map_u = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_map_c = {"N": 0.85, "L": 0.68, "H": 0.50}
        ui_map = {"N": 0.85, "R": 0.62}
        c_map = {"H": 0.56, "L": 0.22, "N": 0.0}

        scope = parts.get("S", "U")
        av = av_map.get(parts.get("AV", "N"), 0.85)
        ac = ac_map.get(parts.get("AC", "L"), 0.77)
        pr = (pr_map_c if scope == "C" else pr_map_u).get(parts.get("PR", "N"), 0.85)
        ui = ui_map.get(parts.get("UI", "N"), 0.85)

        c = c_map.get(parts.get("C", "N"), 0.0)
        i = c_map.get(parts.get("I", "N"), 0.0)
        a = c_map.get(parts.get("A", "N"), 0.0)

        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        exploitability = 8.22 * av * ac * pr * ui
        if impact <= 0:
            return 0.0
        import math
        if scope == "U":
            base = min(impact + exploitability, 10.0)
        else:
            base = min(1.08 * (impact + exploitability), 10.0)
        return round(math.ceil(base * 10) / 10, 1)
    except Exception:
        return None


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

        CHUNK_SIZE = 150
        async with httpx.AsyncClient() as client:
            for chunk_start in range(0, len(components), CHUNK_SIZE):
                chunk_components = components[chunk_start:chunk_start + CHUNK_SIZE]
                queries = []
                for c in chunk_components:
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

                try:
                    response = await client.post(self.batch_url, json=payload, timeout=30.0)
                    response.raise_for_status()
                    data = response.json()

                    batch_results = data.get("results", [])
                    for i, result in enumerate(batch_results):
                        purl_str = chunk_components[i].canonical
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
                            if purl_str not in results:
                                results[purl_str] = []
                            results[purl_str].extend(vuln_models)
                except Exception as e:
                    print(f"OSV Client batch error: {e}")
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
            
    def _extract_severity(self, data: Dict[str, Any]) -> tuple[Severity, Optional[float], Optional[str]]:
        """
        Determines exact severity enum, cvss_score, and cvss_vector from OSV data.
        Maps MODERATE -> MEDIUM (GitHub Advisory standard).
        Computes CVSS score from CVSS:3 vector if available.
        """
        cvss_score: Optional[float] = None
        cvss_vector: Optional[str] = None

        # 1. Check raw severity string in database_specific or ecosystem_specific
        raw_sev = None
        db_spec = data.get("database_specific")
        if isinstance(db_spec, dict) and db_spec.get("severity"):
            raw_sev = str(db_spec["severity"]).upper().strip()
        if not raw_sev:
            eco_spec = data.get("ecosystem_specific")
            if isinstance(eco_spec, dict) and eco_spec.get("severity"):
                raw_sev = str(eco_spec["severity"]).upper().strip()

        # 2. Check CVSS vectors / scores in data.get("severity", [])
        severities = data.get("severity", []) or []
        for sev in severities:
            score_val = sev.get("score")
            if not score_val:
                continue
            if sev.get("type") in ("CVSS_V3", "CVSS_V3.0", "CVSS_V3.1") or "CVSS:3" in str(score_val):
                cvss_vector = str(score_val)
                cvss_score = compute_cvss3_score(cvss_vector)
                break
            elif sev.get("type") in ("CVSS_V4", "CVSS_V2"):
                cvss_vector = str(score_val)

        # 3. Resolve severity enum
        if raw_sev:
            if raw_sev in ("MODERATE", "MEDIUM"):
                return Severity.MEDIUM, cvss_score, cvss_vector
            elif raw_sev == "CRITICAL":
                return Severity.CRITICAL, cvss_score, cvss_vector
            elif raw_sev == "HIGH":
                return Severity.HIGH, cvss_score, cvss_vector
            elif raw_sev == "LOW":
                return Severity.LOW, cvss_score, cvss_vector
            elif raw_sev == "NONE":
                return Severity.NONE, cvss_score, cvss_vector

        # Fallback to CVSS score mapping
        if cvss_score is not None:
            if cvss_score >= 9.0:
                return Severity.CRITICAL, cvss_score, cvss_vector
            elif cvss_score >= 7.0:
                return Severity.HIGH, cvss_score, cvss_vector
            elif cvss_score >= 4.0:
                return Severity.MEDIUM, cvss_score, cvss_vector
            elif cvss_score > 0.0:
                return Severity.LOW, cvss_score, cvss_vector

        return Severity.MEDIUM, cvss_score, cvss_vector

    def _parse_vuln(self, data: Dict[str, Any]) -> VulnerabilityModel:
        severity_enum, cvss_score, cvss_vector = self._extract_severity(data)

        # Summary resolution with details fallback
        summary = data.get("summary")
        if not summary or str(summary).strip() in ("", "No summary provided", "None"):
            details = data.get("details") or ""
            if details:
                first_sent = details.strip().split("\n")[0].split(". ")[0].strip()
                if first_sent:
                    summary = first_sent + ("." if not first_sent.endswith(".") else "")
                else:
                    summary = details[:120].strip() + "..."
            else:
                summary = f"Security vulnerability advisory {data.get('id', '')}"
        else:
            summary = str(summary).strip()

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
        all_fixes = []
        
        for affected in data.get("affected", []):
            eco = affected.get("package", {}).get("ecosystem")
            if eco and eco not in affected_ecosystems:
                affected_ecosystems.append(eco)
                
            ranges = affected.get("ranges", [])
            for r in ranges:
                for event in r.get("events", []):
                    if "fixed" in event and event["fixed"]:
                        f_ver = str(event["fixed"]).strip()
                        if f_ver and f_ver not in all_fixes:
                            all_fixes.append(f_ver)
                        eco_key = eco or "unknown"
                        if eco_key not in fixed_versions:
                            fixed_versions[eco_key] = f_ver
                        elif isinstance(fixed_versions[eco_key], list):
                            if f_ver not in fixed_versions[eco_key]:
                                fixed_versions[eco_key].append(f_ver)
                        elif fixed_versions[eco_key] != f_ver:
                            fixed_versions[eco_key] = [fixed_versions[eco_key], f_ver]

        if all_fixes:
            fixed_versions["_all_fixes"] = all_fixes

        aliases = data.get("aliases", [])
        for alias in aliases:
            if alias.startswith("CWE-"):
                cwe_ids.append(alias)
                
        return VulnerabilityModel(
            osv_id=data.get("id", ""),
            aliases=aliases,
            summary=summary,
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
