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

export async function fetchRepositoryAnalysis(githubUrl: string): Promise<AnalysisResponse> {
  const response = await fetch(`${API_BASE}/api/v1/analyze`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ github_url: githubUrl }),
  });

  if (!response.ok) {
    let errorDetail = response.statusText;
    try {
      const errorBody = await response.json();
      if (errorBody.detail) errorDetail = errorBody.detail;
    } catch (e) {}
    throw new Error(`API error: ${errorDetail}`);
  }

  return response.json();
}

export async function fetchFolderAnalysis(
  projectName: string,
  files: { path: string; content: string }[]
): Promise<AnalysisResponse> {
  const response = await fetch(`${API_BASE}/api/v1/analyze/folder`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ project_name: projectName, files, enable_code_review: true }),
  });

  if (!response.ok) {
    let errorDetail = response.statusText;
    try {
      const errorBody = await response.json();
      if (errorBody.detail) errorDetail = errorBody.detail;
    } catch (e) {}
    throw new Error(`API error: ${errorDetail}`);
  }

  return response.json();
}

export async function fetchCodeReviewSnippet(
  code: string,
  language: string,
  filePath?: string
): Promise<{ reviews: any[]; count: number }> {
  const response = await fetch(`${API_BASE}/api/v1/review/code`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ code, language, file_path: filePath }),
  });

  if (!response.ok) {
    throw new Error(`Review error: ${response.statusText}`);
  }

  return response.json();
}

export async function executeSandbox(
  req: import("@/types").SandboxExecutionRequest
): Promise<import("@/types").SandboxExecutionResponse> {
  const response = await fetch(`${API_BASE}/api/v1/execute/sandbox`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(req),
  });

  if (!response.ok) {
    let errorDetail = response.statusText;
    try {
      const errorBody = await response.json();
      if (errorBody.detail) errorDetail = errorBody.detail;
    } catch (e) {}
    throw new Error(`Sandbox execution error: ${errorDetail}`);
  }

  return response.json();
}

