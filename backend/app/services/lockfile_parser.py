# SupplyGraph - Lockfile Parser
from app.models.core import SBOMComponent, Ecosystem, PURL
from typing import List, Dict, Any
import json
import toml
import re

class LockfileParser:
    def parse_lockfile(self, content: str, filename: str) -> List[SBOMComponent]:
        if filename.endswith("package-lock.json"):
            return self._parse_package_lock_json(content)
        elif filename.endswith("poetry.lock"):
            return self._parse_poetry_lock(content)
        elif filename.endswith("requirements.txt"):
            return self._parse_requirements_txt(content)
        else:
            raise ValueError(f"Unsupported lockfile format: {filename}")

    def _parse_package_lock_json(self, content: str) -> List[SBOMComponent]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []

        components = []
        
        # Parse v2 and v3 package-lock.json
        if 'packages' in data:
            for path, pkg in data['packages'].items():
                if not path:
                    continue  # Root project
                name = pkg.get("name")
                if not name:
                    name = path.split('node_modules/')[-1]
                
                version = pkg.get("version")
                if name and version:
                    purl_obj = PURL(ecosystem=Ecosystem.NPM, name=name, version=version)
                    components.append(
                        SBOMComponent(
                            bom_ref=str(purl_obj),
                            name=name,
                            version=version,
                            ecosystem=Ecosystem.NPM,
                            purl=str(purl_obj)
                        )
                    )
        # Parse v1 package-lock.json
        elif 'dependencies' in data:
            def extract_deps(deps: Dict[str, Any]):
                for name, pkg in deps.items():
                    version = pkg.get("version")
                    if version:
                        purl_obj = PURL(ecosystem=Ecosystem.NPM, name=name, version=version)
                        components.append(
                        SBOMComponent(
                            bom_ref=str(purl_obj),
                            name=name,
                                version=version,
                                ecosystem=Ecosystem.NPM,
                                purl=str(purl_obj)
                            )
                        )
                    if 'dependencies' in pkg:
                        extract_deps(pkg['dependencies'])
            extract_deps(data['dependencies'])

        # Deduplicate
        seen = set()
        unique_components = []
        for c in components:
            if c.purl not in seen:
                seen.add(c.purl)
                unique_components.append(c)
                
        return unique_components

    def _parse_poetry_lock(self, content: str) -> List[SBOMComponent]:
        try:
            data = toml.loads(content)
        except Exception:
            return []

        components = []
        packages = data.get("package", [])
        
        for pkg in packages:
            name = pkg.get("name")
            version = pkg.get("version")
            if name and version:
                purl_obj = PURL(ecosystem=Ecosystem.PYPI, name=name, version=version)
                components.append(
                        SBOMComponent(
                            bom_ref=str(purl_obj),
                            name=name,
                        version=version,
                        ecosystem=Ecosystem.PYPI,
                        purl=str(purl_obj)
                    )
                )
                
        return components

    def _parse_requirements_txt(self, content: str) -> List[SBOMComponent]:
        components = []
        lines = content.splitlines()
        
        req_pattern = re.compile(r'^([a-zA-Z0-9_\-\.]+)(?:==|>=|<=|~=)([\w\-\.]+)$')
        
        for line in lines:
            line = line.split('#')[0].strip()
            line = line.split(';')[0].strip()
            
            if not line:
                continue
                
            if '==' in line:
                parts = line.split('==')
                name = parts[0].strip()
                version = parts[1].strip()
                purl_obj = PURL(ecosystem=Ecosystem.PYPI, name=name, version=version)
                components.append(
                        SBOMComponent(
                            bom_ref=str(purl_obj),
                            name=name,
                        version=version,
                        ecosystem=Ecosystem.PYPI,
                        purl=str(purl_obj)
                    )
                )
            else:
                match = req_pattern.match(line)
                if match:
                    name = match.group(1)
                    version = match.group(2)
                    purl_obj = PURL(ecosystem=Ecosystem.PYPI, name=name, version=version)
                    components.append(
                        SBOMComponent(
                            bom_ref=str(purl_obj),
                            name=name,
                            version=version,
                            ecosystem=Ecosystem.PYPI,
                            purl=str(purl_obj)
                        )
                    )
                    
        return components

