# SupplyGraph
**HackFusion 2026 — Theme 6: Software Supply-Chain Attack Graph Engine**

SupplyGraph is an evidence-driven software supply-chain attack graph engine. It parses dependencies, pulls live threat intelligence from OSV, runs static AST analysis on code, detects typosquatting, and generates a mathematically rigorous NetworkX dependency graph to trace attack paths to your production assets.

## Quickstart

### Prerequisites
- Python 3.11+
- Node.js 20+

### Installation
1. Install backend dependencies:
```powershell
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

2. Install frontend dependencies:
```powershell
cd frontend
npm install
```

### Running the App
On Windows, you can start both the frontend and backend simultaneously using the provided script:
```powershell
.\start-all.ps1
```

Or manually:
- **Backend:** `cd backend; .\venv\Scripts\python -m uvicorn app.main:app --reload`
- **Frontend:** `cd frontend; npm run dev`

### Access
- Frontend Dashboard: [http://localhost:3000](http://localhost:3000)
- Backend API Docs: [http://localhost:8000/docs](http://localhost:8000/docs)

## Key Features
- **Server-Side Layout:** Deterministic graph positioning calculated in Python using topological sorts.
- **Evidence-Driven Detection:** Strict classification schema (FACT, HEURISTIC, SIMULATED) prevents hallucinated CVEs.
- **AI Explanation Layer:** Google Gemini analyzes the attack path and summarizes it without fabricating context.
- **Multi-Level Attack Path Tracing:** Identifies how deep transitive dependencies compromise top-level services.
