import { AnalysisResponse } from "@/types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export async function fetchDemoAnalysis(scenarioId: string): Promise<AnalysisResponse> {
  const response = await fetch(`${API_BASE}/api/v1/analyze/demo`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ scenario_id: scenarioId }),
  });

  if (!response.ok) {
    throw new Error(`API error: ${response.statusText}`);
  }

  return response.json();
}
