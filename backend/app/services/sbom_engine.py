from app.models.core import SBOM, SBOMComponent, SBOMDependency, Ecosystem, PURL
from typing import List, Dict
from datetime import datetime, timezone
import uuid

class SBOMEngine:
    def __init__(self):
        pass

    def build_sbom(self, components: List[SBOMComponent], project_name: str = "Unknown Project", project_version: str = "0.0.0") -> SBOM:
        project_purl = str(PURL(ecosystem=Ecosystem.PYPI, name=project_name.lower().replace(" ", "-"), version=project_version))
        
        unique_components: Dict[str, SBOMComponent] = {}
        for comp in components:
            if comp.purl not in unique_components:
                unique_components[comp.purl] = comp
                
        final_components = list(unique_components.values())
        
        dependencies = []
        for comp in final_components:
            dependencies.append(
                SBOMDependency(
                    from_bom_ref=project_purl,
                    to_bom_ref=comp.bom_ref,
                    is_direct=True
                )
            )
        
        return SBOM(
            metadata={"name": project_name, "version": project_version},
            components=final_components,
            dependencies=dependencies
        )
