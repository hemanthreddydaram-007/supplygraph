# SupplyGraph - SBOM Engine
from app.models.core import SBOM, SBOMComponent, SBOMDependency, Ecosystem, PURL
from typing import List, Dict
from datetime import datetime, timezone
import uuid

class SBOMEngine:
    def __init__(self):
        pass

    def build_sbom(self, components: List[SBOMComponent], project_name: str = "Unknown Project", project_version: str = "0.0.0") -> SBOM:
        # Create a PURL for the project itself
        project_purl = str(PURL(ecosystem=Ecosystem.PYPI, name=project_name.lower().replace(" ", "-"), version=project_version))
        
        # Deduplicate components based on PURL
        unique_components: Dict[str, SBOMComponent] = {}
        for comp in components:
            if comp.purl not in unique_components:
                unique_components[comp.purl] = comp
                
        final_components = list(unique_components.values())
        
        # Build dependency graph
        dependencies = self._build_dependencies(project_purl, final_components)
        
        return SBOM(
            id=str(uuid.uuid4()),
            name=project_name,
            version=project_version,
            timestamp=datetime.now(timezone.utc),
            components=final_components,
            dependencies=dependencies
        )

    def _build_dependencies(self, root_purl: str, components: List[SBOMComponent]) -> List[SBOMDependency]:
        """
        Builds a flat dependency graph where all components are direct dependencies
        of the root project. For more advanced tree structures (like package-lock.json v3),
        we would trace the parent-child relationships here.
        """
        dependencies = []
        
        if components:
            dep_refs = [comp.purl for comp in components]
            dependencies.append(
                SBOMDependency(
                    ref=root_purl,
                    dependsOn=dep_refs
                )
            )
            
        return dependencies
