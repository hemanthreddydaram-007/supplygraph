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

export async function fetchRepositoryAnalysis(
  githubUrl: string,
  productionOnly?: boolean,
  maxTransitiveDepth?: number,
  signal?: AbortSignal
): Promise<AnalysisResponse> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 40000);
  
  const onExternalAbort = () => controller.abort();
  if (signal) {
    if (signal.aborted) {
      controller.abort();
    } else {
      signal.addEventListener("abort", onExternalAbort);
    }
  }

  try {
    const response = await fetch(`${API_BASE}/api/v1/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        github_url: githubUrl,
        production_only: Boolean(productionOnly),
        max_transitive_depth: maxTransitiveDepth ?? 10,
      }),
      signal: controller.signal,
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
  } catch (err: any) {
    if (err.name === "AbortError" && !signal?.aborted) {
      throw new Error(
        "Repository analysis request timed out after 40 seconds. " +
        "Tip: Upload the repository folder via '📂 Upload Folder' to analyze all dependencies locally with zero rate limits."
      );
    }
    throw err;
  } finally {
    clearTimeout(timeoutId);
    if (signal) {
      signal.removeEventListener("abort", onExternalAbort);
    }
  }
}

export async function fetchFolderAnalysis(
  projectName: string,
  files: { path: string; content: string }[],
  productionOnly?: boolean,
  maxTransitiveDepth?: number
): Promise<AnalysisResponse> {
  const response = await fetch(`${API_BASE}/api/v1/analyze/folder`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      project_name: projectName,
      files,
      enable_code_review: true,
      production_only: Boolean(productionOnly),
      max_transitive_depth: maxTransitiveDepth ?? 10,
    }),
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

export async function compareScans(
  scanA: AnalysisResponse,
  scanB: AnalysisResponse
): Promise<any> {
  const response = await fetch(`${API_BASE}/api/v1/compare`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ scan_a: scanA, scan_b: scanB }),
  });

  if (!response.ok) {
    throw new Error(`Comparison error: ${response.statusText}`);
  }

  return response.json();
}


