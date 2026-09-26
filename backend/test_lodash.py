import asyncio
from app.services.analysis_service import AnalysisService
from app.models.core import AnalysisRequest

async def test():
    svc = AnalysisService()
    req = AnalysisRequest(github_url="https://github.com/mtn6807/vulnerable", branch="master")
    res = await svc.run_analysis(req)
    for c in res.components:
        if 'lodash' in c.name:
            print("PURL:", c.purl)

asyncio.run(test())
