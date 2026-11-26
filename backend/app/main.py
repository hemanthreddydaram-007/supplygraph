# SupplyGraph - Main FastAPI Application
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
