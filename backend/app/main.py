# SupplyGraph - Main FastAPI Application
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import get_settings
from app.api.router import api_router
from app.api.endpoints import router as health_router # just for /health if at root

def create_application() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Evidence-driven software supply-chain attack analysis.",
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
    return {"status": "ok", "version": "1.0.0"}
