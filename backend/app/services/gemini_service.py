# SupplyGraph - AI Triage Engine
# Supports: Google Gemini 2.5 Flash + AWS Bedrock (Claude 3.5)
from app.models.core import AnalysisResponse
from app.core.config import get_settings
import json
import logging

logger = logging.getLogger(__name__)


class GeminiService:
    """Multi-provider AI executive triage engine."""

    def __init__(self):
        self.settings = get_settings()
        self.gemini_available = False
        self.bedrock_available = False
        self.model_provider = "Fallback (No AI keys configured)"

        # Try initializing Google Gemini
        try:
            if self.settings.gemini_api_key:
                import google.generativeai as genai
                genai.configure(api_key=self.settings.gemini_api_key)
                self.gemini_model = genai.GenerativeModel('gemini-2.5-flash')
                self.gemini_available = True
                self.model_provider = "Gemini 2.5 Flash"
                logger.info("Gemini 2.5 Flash initialized.")
        except Exception as e:
            logger.warning(f"Gemini init failed: {e}")

        # Try initializing AWS Bedrock (Claude 3.5 Sonnet)
        try:
            import os
            aws_key = os.environ.get("AWS_ACCESS_KEY_ID") or getattr(self.settings, "aws_access_key_id", None)
            aws_secret = os.environ.get("AWS_SECRET_ACCESS_KEY") or getattr(self.settings, "aws_secret_access_key", None)
            aws_region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

            if aws_key and aws_secret:
                import boto3
                self.bedrock_client = boto3.client(
                    service_name="bedrock-runtime",
                    region_name=aws_region,
                    aws_access_key_id=aws_key,
                    aws_secret_access_key=aws_secret
                )
                self.bedrock_available = True
                if self.gemini_available:
                    self.model_provider = "AWS Bedrock (Claude 3.5) + Gemini 2.5 Flash"
                else:
                    self.model_provider = "AWS Bedrock (Claude 3.5 Sonnet)"
                logger.info("AWS Bedrock initialized.")
        except Exception as e:
            logger.warning(f"AWS Bedrock init failed (likely missing boto3 or credentials): {e}")

    async def generate_explanation(self, analysis_response: AnalysisResponse) -> str:
        """
        Generate an executive-level AI security briefing.
        Tries AWS Bedrock first, falls back to Gemini, then to deterministic summary.
        """
        prompt = self._build_prompt(analysis_response)

        import asyncio
        # Try AWS Bedrock (Claude 3.5) first with strict 4.0s timeout
        if self.bedrock_available:
            try:
                result = await asyncio.wait_for(self._query_bedrock(prompt), timeout=4.0)
                if result:
                    return result
            except Exception as e:
                logger.warning(f"Bedrock query failed or timed out, falling back to Gemini: {e}")

        # Try Gemini with strict 4.0s timeout
        if self.gemini_available:
            try:
                result = await asyncio.wait_for(self._query_gemini(prompt), timeout=4.0)
                if result:
                    return result
            except Exception as e:
                logger.warning(f"Gemini query failed or timed out, using deterministic fallback: {e}")

        # Deterministic fallback
        return self._deterministic_summary(analysis_response)

    async def _query_bedrock(self, prompt: str) -> str:
        """Query AWS Bedrock Claude 3.5 Sonnet."""
        import asyncio
        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 1024,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        })

        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self.bedrock_client.invoke_model(
                body=body,
                modelId="anthropic.claude-3-5-sonnet-20241022-v2:0",
                accept="application/json",
                contentType="application/json"
            )
        )
        result_body = json.loads(response["body"].read())
        return result_body["content"][0]["text"]

    async def _query_gemini(self, prompt: str) -> str:
        """Query Google Gemini 2.5 Flash."""
        response = await self.gemini_model.generate_content_async(prompt)
        return response.text

    def _build_prompt(self, analysis_response: AnalysisResponse) -> str:
        """Build a focused, bounded prompt that prevents hallucination."""
        try:
            # Only send the essential fields to avoid token limits
            payload = {
                "repository": analysis_response.scan.repository_url,
                "total_components": analysis_response.scan.total_components,
                "total_findings": analysis_response.scan.total_findings,
                "blast_radius_score": analysis_response.scan.blast_radius_score,
                "findings_summary": [
                    {
                        "title": f.title,
                        "severity": f.severity,
                        "type": f.finding_type,
                        "description": f.description[:200]
                    }
                    for f in analysis_response.findings[:10]  # Cap at 10
                ]
            }
            payload_str = json.dumps(payload, indent=2, default=str)
        except Exception:
            payload_str = "Analysis data unavailable."

        return (
            "You are a CISO-level AI security analyst. Based STRICTLY on the provided JSON data, "
            "write a 3-4 paragraph executive security briefing. "
            "DO NOT invent, fabricate, or assume any CVEs, vulnerabilities, or evidence not present in the data. "
            "Focus on: (1) overall risk posture, (2) the most critical findings, "
            "(3) immediate containment priorities, (4) strategic recommendations.\n\n"
            f"Analysis Data:\n{payload_str}"
        )

    def _deterministic_summary(self, analysis_response: AnalysisResponse) -> str:
        """Deterministic fallback when no AI provider is available."""
        r = analysis_response
        total = r.scan.total_findings
        blast = r.scan.blast_radius_score
        components = r.scan.total_components
        repo = r.scan.repository_url

        critical = sum(1 for f in r.findings if getattr(f, 'severity', '') in ('CRITICAL', 'HIGH'))

        lines = [
            f"**SupplyGraph Security Analysis — {repo.split('/')[-1] if repo else 'Repository'}**",
            "",
            f"Scanned {components} components across the dependency tree. "
            f"Identified {total} security finding(s) with a calculated Blast Radius of {blast:.1f}/100.",
            "",
        ]

        if total == 0:
            lines.append(
                "No security findings were detected by the configured analyzers. "
                "The dependency tree appears clean based on current OSV intelligence, "
                "static analysis, and pattern detection."
            )
        else:
            lines.append(
                f"{critical} high/critical severity finding(s) require immediate attention. "
                "Review the Findings panel for detailed evidence and containment strategies. "
                "Apply the recommended lockfile overrides to pin vulnerable packages to safe versions."
            )
            lines.append("")
            lines.append(
                "SupplyGraph's evidence-bounded analysis ensures all findings are backed by "
                "verifiable evidence from OSV.dev, static AST analysis, or CI/CD workflow inspection. "
                "No findings are fabricated or inferred without supporting data."
            )

        lines.append("")
        lines.append(f"*Model: {self.model_provider} | Analysis: Zero-Hallucination Bounded*")
        return "\n".join(lines)
