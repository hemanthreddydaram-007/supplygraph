# SupplyGraph - Main FastAPI Application
#
# ROOT CHALLENGE:
#   Developers using AI coding assistants routinely deploy applications to production
#   without visibility into which open-source dependencies carry exploitable vulnerabilities,
#   which are reachable through real call paths, or which contain malicious lifecycle hooks.
#
# CORE OBJECTIVES SERVED BY THIS MODULE:
#   - Objective 6: Unified multi-ecosystem observability (single entry-point /api/v1/scan)
#   - All objectives: API gateway routing all analysis, sandbox, SBOM, and review endpoints
#
# USER NEEDS ADDRESSED:
#   - Developer Need: One scan covers npm, PyPI, Go, GitHub Actions
#   - Reviewer Need: Instant access via /api/docs OpenAPI Swagger UI
#   - DevSecOps Need: REST API for CI/CD pipeline integration
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import get_settings
from app.api.router import api_router
from app.api.endpoints import router as health_router  # just for /health if at root

def create_application() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "SupplyGraph — Zero-Trust Application Security Posture Management (ASPM) "
            "& Software Supply-Chain Attack Graph. "
            "Evidence-driven analysis combining multi-ecosystem lockfile ingestion, "
            "deterministic Reverse DAG reachability, Blast-Radius scoring, "
            "CycloneDX v1.5 SBOM generation, and line-level AI code auto-patching."
        ),
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    app.include_router(api_router)
    return app

app = create_application()

@app.get("/health")
def health_check():
    settings = get_settings()
    return {"status": "ok", "version": settings.app_version}
