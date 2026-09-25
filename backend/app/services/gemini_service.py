# SupplyGraph - Gemini Explanation Service
from app.models.core import AnalysisResponse
from app.core.config import get_settings
import google.generativeai as genai
import json
import logging

logger = logging.getLogger(__name__)

class GeminiService:
    def __init__(self):
        self.settings = get_settings()
        self.gemini_available = bool(self.settings.gemini_api_key)
        if self.gemini_available:
            genai.configure(api_key=self.settings.gemini_api_key)
            self.model = genai.GenerativeModel('gemini-1.5-flash')
        else:
            self.model = None

    async def generate_explanation(self, analysis_response: AnalysisResponse) -> str:
        if not self.gemini_available or not self.settings.gemini_api_key:
            self.gemini_available = False
            return "Gemini API key not configured. Explanation generation is disabled. Please review the raw analysis data."

        try:
            analysis_data = analysis_response.model_dump(mode="json")
            payload = json.dumps(analysis_data, indent=2)

            prompt = (
                "You are an explainable AI security assistant. Read the following JSON payload "
                "representing a software supply-chain attack graph. Summarize the attack path "
                "and impact in 3-4 concise paragraphs. DO NOT invent or fabricate any "
                "vulnerabilities, CVEs, or evidence. Only rely on the provided JSON data.\n\n"
                f"JSON Payload:\n{payload}"
            )

            # Note: generate_content_async is preferred for async methods, 
            # but standard generate_content works as well. Using async here.
            response = await self.model.generate_content_async(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Error generating explanation from Gemini: {e}")
            return f"Failed to generate explanation due to an internal error."
