# SupplyGraph - OSV Intelligence Engine v3.0
# Batch querying with persistent cache and SemVer-aware fixed version resolution
from app.models.core import VulnerabilityModel, PURL, Severity
from app.core.config import get_settings
from typing import List, Dict, Any, Optional, Tuple, Set
import asyncio
import httpx
import json
import os
import re
import logging
import aiofiles
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


def normalize_pypi_name(name: str) -> str:
    """Normalizes PyPI package names per PEP 503."""
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def resolve_best_fixed_version(
    installed_version: Optional[str],
    candidate_fixes: List[str],
    prefer_highest: bool = False
) -> Optional[str]:
    """
    Selects the least disruptive patched SemVer fix without ever downgrading major versions.
    1. Prefer patched version within the same major version > installed_version.
       If prefer_highest is True, selects the highest patch in same major (covering all CVEs).
    2. Otherwise, prefer lowest patched version in higher major versions (> installed_version).
    3. Never recommend a major downgrade or equal version.
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

    # 1. Candidate fixes with same major and strictly > installed_version
    same_major_upgrades = [
        (v, raw) for v, raw in valid_fixes
        if getattr(v, "major", None) == inst_major and v > inst_v
    ]
    if same_major_upgrades:
        same_major_upgrades.sort(key=lambda x: x[0], reverse=prefer_highest)
        return same_major_upgrades[0][1]

    # 2. Candidate fixes with higher major and strictly > installed_version
    higher_major_upgrades = [
        (v, raw) for v, raw in valid_fixes
        if inst_major is not None and getattr(v, "major", 0) > inst_major and v > inst_v
    ]
    if higher_major_upgrades:
        higher_major_upgrades.sort(key=lambda x: x[0])
        return higher_major_upgrades[0][1]

    # 3. If all fixes are lower than or equal to installed (e.g. backports to older branches),
    # do NOT downgrade and do NOT fabricate non-existent versions. Return None so caller knows no fix exists.
    return None


def merge_aliased_records(
    records: List[Dict[str, Any]],
    target_pkg_name: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Groups and merges OSV records that share any ID in [id, ...aliases].
    Prefers GHSA-* as the primary display ID, combines all aliases,
    selects the most informative human summary, and preserves all fixed version events.
    """
    if not records:
        return []

    groups: List[Dict[str, Any]] = []
    for r in records:
        r_id = r.get("id", "")
        r_aliases = [a for a in r.get("aliases", []) if a]
        all_ids = set([r_id] + r_aliases) if r_id else set(r_aliases)
        if not all_ids:
            groups.append({"ids": set(), "records": [r]})
            continue

        matched_groups = [g for g in groups if g["ids"] & all_ids]
        if not matched_groups:
            groups.append({"ids": all_ids, "records": [r]})
        elif len(matched_groups) == 1:
            matched_groups[0]["ids"].update(all_ids)
            matched_groups[0]["records"].append(r)
        else:
            merged_ids = set(all_ids)
            merged_records = [r]
            for mg in matched_groups:
                merged_ids.update(mg["ids"])
                merged_records.extend(mg["records"])
                groups.remove(mg)
            groups.append({"ids": merged_ids, "records": merged_records})

    merged_vulns = []
    for g in groups:
        group_records = g["records"]
        if len(group_records) == 1:
            merged_vulns.append(group_records[0])
            continue

        def id_priority(vid: str) -> Tuple[int, str]:
            if vid.startswith("GHSA-"):
                return (0, vid)
            if vid.startswith("CVE-"):
                return (1, vid)
            if vid.startswith("PYSEC-"):
                return (2, vid)
            return (3, vid)

        all_group_ids = [r.get("id") for r in group_records if r.get("id")]
        all_group_ids.sort(key=id_priority)
        primary_id = all_group_ids[0] if all_group_ids else group_records[0].get("id", "")

        ghsa_recs = [r for r in group_records if r.get("id", "").startswith("GHSA-")]
        primary_rec = ghsa_recs[0] if ghsa_recs else group_records[0]

        combined_aliases = set()
        for r in group_records:
            if r.get("id") and r["id"] != primary_id:
                combined_aliases.add(r["id"])
            for a in r.get("aliases", []):
                if a and a != primary_id:
                    combined_aliases.add(a)

        best_summary = None
        for r in (ghsa_recs + group_records):
            s = r.get("summary")
            if s and str(s).strip() and str(s).strip() not in ("None", "No summary provided"):
                best_summary = str(s).strip()
                break
        if not best_summary:
            for r in (ghsa_recs + group_records):
                d = r.get("details")
                if d and str(d).strip():
                    first_sent = d.strip().split("\n")[0].split(". ")[0].strip()
                    if first_sent:
                        best_summary = first_sent + ("." if not first_sent.endswith(".") else "")
                        break

        best_details = primary_rec.get("details")
        for r in group_records:
            d = r.get("details")
            if d and (not best_details or len(d) > len(best_details)):
                best_details = d

        seen_refs = set()
        merged_refs = []
        for r in group_records:
            for ref in r.get("references", []):
                u = ref.get("url")
                if u and u not in seen_refs:
                    seen_refs.add(u)
                    merged_refs.append(ref)

        merged_affected = []
        for r in group_records:
            for aff in r.get("affected", []):
                merged_affected.append(aff)

        merged_sev = primary_rec.get("severity") or []
        merged_db_spec = primary_rec.get("database_specific") or {}
        if not merged_sev:
            for r in group_records:
                if r.get("severity"):
                    merged_sev = r.get("severity")
                    break
        if not merged_db_spec:
            for r in group_records:
                if r.get("database_specific"):
                    merged_db_spec = r.get("database_specific")
                    break

        merged_rec = {
            "id": primary_id,
            "aliases": sorted(list(combined_aliases)),
            "summary": best_summary or primary_rec.get("summary"),
            "details": best_details,
            "severity": merged_sev,
            "database_specific": merged_db_spec,
            "ecosystem_specific": primary_rec.get("ecosystem_specific", {}),
            "references": merged_refs,
            "affected": merged_affected,
            "published": primary_rec.get("published"),
            "modified": primary_rec.get("modified"),
            "schema_version": primary_rec.get("schema_version", "1.6.0"),
        }
        merged_vulns.append(merged_rec)

    return merged_vulns


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

        # Group components by canonical purl to avoid redundant network queries
        unique_components: Dict[str, PURL] = {}
        for c in components:
            if c.canonical not in unique_components:
                unique_components[c.canonical] = c

        comp_list = list(unique_components.values())

        eco_map = {
            "npm": "npm",
            "pypi": "PyPI",
            "maven": "Maven",
            "golang": "Go",
            "cargo": "crates.io",
            "nuget": "NuGet"
        }

        # For typical repositories (<= 60 components), query POST /v1/query concurrently.
        # This returns the complete vulnerability payload (id, summary, details, aliases, affected, severity)
        # in a single request per component without needing secondary /v1/vulns/{id} calls.
        if len(comp_list) <= 60:
            sem = asyncio.Semaphore(10)
            async with httpx.AsyncClient(timeout=10.0) as client:
                async def _query_single(comp: PURL) -> Tuple[str, List[VulnerabilityModel]]:
                    eco_str = eco_map.get(comp.ecosystem.value, comp.ecosystem.value) if comp.ecosystem else "PyPI"
                    pkg_name = f"{comp.namespace}/{comp.name}" if comp.namespace else comp.name
                    payload: Dict[str, Any] = {
                        "package": {"name": pkg_name, "ecosystem": eco_str}
                    }
                    if comp.version:
                        payload["version"] = comp.version

                    raw_vulns: List[Dict[str, Any]] = []
                    async with sem:
                        for attempt in range(3):
                            try:
                                resp = await client.post("https://api.osv.dev/v1/query", json=payload, timeout=10.0)
                                if resp.status_code == 200:
                                    raw_vulns = resp.json().get("vulns", [])
                                    # Cache full vulnerability records on disk
                                    for rv in raw_vulns:
                                        vid = rv.get("id")
                                        if vid:
                                            cache_path = self.cache_dir / f"{vid}.json"
                                            if not cache_path.exists():
                                                try:
                                                    async with aiofiles.open(cache_path, "w") as f:
                                                        await f.write(json.dumps(rv))
                                                except Exception:
                                                    pass
                                    break
                            except Exception:
                                if attempt < 2:
                                    await asyncio.sleep(0.3 * (2 ** attempt))
                                else:
                                    pass

                    if not raw_vulns:
                        return comp.canonical, []

                    # Run alias deduplication on full hydrated records
                    merged_records = merge_aliased_records(raw_vulns, target_pkg_name=comp.name)
                    models = []
                    for mrec in merged_records:
                        try:
                            models.append(self._parse_vuln(mrec, target_pkg_name=comp.name))
                        except Exception:
                            pass
                    return comp.canonical, models

                tasks = [_query_single(c) for c in comp_list]
                outputs = await asyncio.gather(*tasks, return_exceptions=True)
                for out in outputs:
                    if isinstance(out, tuple) and out[1]:
                        results[out[0]] = out[1]
            return results

        # For larger repositories (> 60 components), use querybatch + full hydration with retry
        CHUNK_SIZE = 300
        sem = asyncio.Semaphore(10)
        async with httpx.AsyncClient(timeout=15.0) as client:
            chunks = [
                comp_list[i:i + CHUNK_SIZE]
                for i in range(0, len(comp_list), CHUNK_SIZE)
            ]

            async def _process_chunk(chunk_components: List[PURL]):
                chunk_res: Dict[str, List[VulnerabilityModel]] = {}
                queries = []
                for c in chunk_components:
                    eco_str = eco_map.get(c.ecosystem.value, c.ecosystem.value) if c.ecosystem else "PyPI"
                    pkg_name = f"{c.namespace}/{c.name}" if c.namespace else c.name
                    q = {"package": {"name": pkg_name, "ecosystem": eco_str}}
                    if c.version:
                        q["version"] = c.version
                    queries.append(q)

                try:
                    resp = await client.post(self.batch_url, json={"queries": queries}, timeout=15.0)
                    resp.raise_for_status()
                    data = resp.json()
                    batch_results = data.get("results", [])

                    # Collect all unique vuln_ids to fetch concurrently (NO truncation)
                    vuln_id_requests = {}
                    for res_item in batch_results:
                        for v in res_item.get("vulns", []):
                            vid = v.get("id")
                            if vid and vid not in vuln_id_requests:
                                vuln_id_requests[vid] = v.get("modified")

                    fetch_tasks = [
                        self._fetch_vuln_detail(client, vid, mod, sem)
                        for vid, mod in vuln_id_requests.items()
                    ]
                    fetch_results = await asyncio.gather(*fetch_tasks, return_exceptions=True)
                    vuln_cache_map = {}
                    for fres in fetch_results:
                        if isinstance(fres, tuple) and fres[1] is not None:
                            vuln_cache_map[fres[0]] = fres[1]

                    for i, result in enumerate(batch_results):
                        purl_str = chunk_components[i].canonical
                        c_name = chunk_components[i].name
                        raw_vulns = []
                        for v in result.get("vulns", []):
                            vid = v.get("id")
                            if vid and vid in vuln_cache_map:
                                raw_vulns.append(vuln_cache_map[vid])
                            elif vid:
                                raw_vulns.append({
                                    "id": vid,
                                    "summary": f"OSV Advisory: {vid}",
                                    "aliases": []
                                })

                        if raw_vulns:
                            merged_records = merge_aliased_records(raw_vulns, target_pkg_name=c_name)
                            chunk_res[purl_str] = [
                                self._parse_vuln(mrec, target_pkg_name=c_name)
                                for mrec in merged_records
                            ]
                except Exception as e:
                    logger.warning(f"OSV Client batch error: {e}")

                return chunk_res

            chunk_outputs = await asyncio.gather(*[_process_chunk(chunk) for chunk in chunks], return_exceptions=True)
            for co in chunk_outputs:
                if isinstance(co, dict):
                    for purl_str, vulns in co.items():
                        if purl_str not in results:
                            results[purl_str] = []
                        results[purl_str].extend(vulns)

        return results

    async def _fetch_vuln_detail(
        self, client: httpx.AsyncClient, vuln_id: str, modified: Optional[str], sem: asyncio.Semaphore
    ) -> Tuple[str, Optional[Dict[str, Any]]]:
        cache_path = self.cache_dir / f"{vuln_id}.json"

        if cache_path.exists():
            try:
                async with aiofiles.open(cache_path, "r") as f:
                    content = await f.read()
                    cached_data = json.loads(content)
                    if not modified or cached_data.get("modified") == modified:
                        return vuln_id, cached_data
            except (json.JSONDecodeError, OSError):
                pass

        async with sem:
            url = self.vuln_url.format(vuln_id)
            for attempt in range(3):
                try:
                    response = await client.get(url, timeout=8.0)
                    if response.status_code == 200:
                        full_vuln = response.json()
                        try:
                            async with aiofiles.open(cache_path, "w") as f:
                                await f.write(json.dumps(full_vuln))
                        except Exception:
                            pass
                        return vuln_id, full_vuln
                    elif response.status_code == 404:
                        return vuln_id, None
                except Exception:
                    if attempt < 2:
                        await asyncio.sleep(0.3 * (2 ** attempt))
                    else:
                        pass
        return vuln_id, None

    async def _get_cached_or_fetch(self, client: httpx.AsyncClient, vuln_id: str, modified: Optional[str]) -> Optional[Dict[str, Any]]:
        sem = asyncio.Semaphore(1)
        _, res = await self._fetch_vuln_detail(client, vuln_id, modified, sem)
        return res
            
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

    def _parse_vuln(self, data: Dict[str, Any], target_pkg_name: Optional[str] = None) -> VulnerabilityModel:
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

        norm_target = normalize_pypi_name(target_pkg_name) if target_pkg_name else None
        all_affected = data.get("affected", []) or []

        # Filter affected items matching target package if target_pkg_name specified
        matching_affected = []
        for aff in all_affected:
            pkg_name = aff.get("package", {}).get("name")
            if not norm_target or not pkg_name:
                matching_affected.append(aff)
            else:
                if normalize_pypi_name(pkg_name) == norm_target or str(pkg_name).lower() == str(target_pkg_name).lower():
                    matching_affected.append(aff)

        eval_affected = matching_affected if matching_affected else all_affected

        for affected in eval_affected:
            eco = affected.get("package", {}).get("ecosystem")
            if eco and eco not in affected_ecosystems:
                affected_ecosystems.append(eco)
                
            ranges = affected.get("ranges", []) or []
            for r in ranges:
                for event in r.get("events", []) or []:
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
