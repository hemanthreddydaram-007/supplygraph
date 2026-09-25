# SupplyGraph - API Endpoints
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from app.models.core import AnalysisRequest, DemoRequest, AnalysisResponse
from app.services.analysis_service import AnalysisService
import json
import os

router = APIRouter(prefix="/api/v1")

@router.post("/analyze", response_model=AnalysisResponse)
async def analyze(request: AnalysisRequest):
    service = AnalysisService()
    try:
        response = await service.run_analysis(request)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/analyze/demo", response_model=AnalysisResponse)
async def analyze_demo(request: DemoRequest):
    scenario_path = os.path.join(
        os.path.dirname(__file__), 
        "..", 
        "scenarios", 
        f"scenario_{request.scenario_id.lower()}.json"
    )
    if not os.path.exists(scenario_path):
        raise HTTPException(status_code=404, detail="Scenario not found")
        
    try:
        with open(scenario_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return AnalysisResponse(**data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load scenario: {str(e)}")

@router.get("/health")
def health():
    return {"status": "ok", "version": "1.0.0"}
