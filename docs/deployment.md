# SupplyGraph — Deployment Guide

> **Evidence-driven software supply-chain attack analysis.**

This document provides complete instructions for setting up the SupplyGraph platform locally for development and deploying it to production using Vercel (frontend), Render (backend), and Supabase (database).

---

## Prerequisites

Ensure the following are available before proceeding:

| Requirement | Version | Purpose |
|------------|---------|---------|
| Node.js | 20+ | Frontend development and build |
| npm | 10+ | Frontend package management |
| Python | 3.11+ | Backend runtime |
| pip | 23+ | Backend package management |
| Git | Any recent | Version control |
| Supabase account | — | Managed PostgreSQL database |
| GitHub Personal Access Token | — | Repository ingestion |
| Google Gemini API Key | — | AI-generated summaries |

### GitHub Personal Access Token

1. Go to GitHub → Settings → Developer Settings → Personal Access Tokens → Fine-grained tokens
2. Create a new token with the following permissions (read-only):
   - Repository: **Contents** (read)
   - Repository: **Metadata** (read)
   - Repository: **Actions** (read) — for workflow file access
3. Copy the token. It begins with `github_pat_` or `ghp_`.

> [!CAUTION]
> Never commit the GitHub token to version control. Store it only as an environment variable on the server.

### Google Gemini API Key

1. Go to [Google AI Studio](https://aistudio.google.com/app/apikey)
2. Create a new API key for the Gemini 1.5 Pro model
3. Copy the key. It begins with `AI`.

### Supabase Project

1. Go to [supabase.com](https://supabase.com) and create a new project
2. Note your: Project URL, anon key, and service role key
3. The service role key begins with `eyJ...` and has elevated privileges — **treat it as a secret**

---

## Environment Variables

### Frontend Environment Variables (`.env.local`)

Create `frontend/.env.local` (never commit this file):

```bash
# URL of the deployed FastAPI backend
# For local development: http://localhost:8000
# For production: https://your-backend.onrender.com
NEXT_PUBLIC_API_URL=https://your-backend.onrender.com
```

> [!NOTE]
> The `NEXT_PUBLIC_` prefix makes this variable available in the browser. This is the **only** environment variable exposed to the browser. All other configuration is backend-only.

A committed example file (`frontend/.env.example`) contains:
```bash
NEXT_PUBLIC_API_URL=http://localhost:8000
```

---

### Backend Environment Variables (`.env`)

Create `backend/.env` (never commit this file):

```bash
# GitHub API Access
# Required for repository ingestion
GITHUB_TOKEN=ghp_your_github_personal_access_token_here

# Google Gemini API
# Required for AI-generated finding summaries
GEMINI_API_KEY=AIzaSy_your_gemini_api_key_here

# Supabase Database
# Required for persisting scan results
SUPABASE_URL=https://your-project-ref.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.your_anon_key
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.your_service_role_key

# Backend URL (used for CORS and self-referencing URLs)
BACKEND_URL=https://your-backend.onrender.com

# CORS: Comma-separated list of allowed frontend origins
ALLOWED_ORIGINS=https://your-frontend.vercel.app,http://localhost:3000

# OSV Cache
# Directory where OSV API responses are cached to disk
OSV_CACHE_DIR=.cache/osv

# Analysis limits (security guards)
MAX_REPO_SIZE_MB=100
MAX_FILES_PER_SCAN=1000
ANALYSIS_TIMEOUT_SECONDS=300

# Optional: Graph layout spacing overrides
# GRAPH_H_SPACING=280
# GRAPH_V_SPACING=120

# Optional: Detection threshold overrides
# THRESHOLD_TYPOSQUAT=0.85
# THRESHOLD_UPDATE_ANOMALY=0.60
# THRESHOLD_NEW_MAINTAINER_DAYS=30
# MAX_TRANSITIVE_DEPTH=10
```

A committed example file (`backend/.env.example`) contains all keys with `your_value_here` placeholders and no real secrets.

---

## Local Development Setup

### Step 1: Clone the Repository

```bash
git clone https://github.com/your-org/supplygraph.git
cd supplygraph
```

---

### Step 2: Backend Setup

#### 2a. Create Python Virtual Environment

```bash
cd backend
python -m venv venv
```

Activate the virtual environment:
- **Windows**: `venv\Scripts\activate`
- **macOS/Linux**: `source venv/bin/activate`

#### 2b. Install Python Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

The `requirements.txt` file includes:
```
fastapi==0.111.0
uvicorn[standard]==0.29.0
httpx==0.27.0
python-dotenv==1.0.1
pydantic==2.7.1
pydantic-settings==2.2.1
networkx==3.3
cyclonedx-python-lib==7.2.0
packageurl-python==0.15.0
rapidfuzz==3.9.3
PyYAML==6.0.1
toml==0.10.2
supabase==2.4.5
google-generativeai==0.7.2
pytest==8.2.0
pytest-asyncio==0.23.6
httpx==0.27.0
```

#### 2c. Configure Environment Variables

```bash
cp .env.example .env
# Edit .env and fill in real values
```

#### 2d. Create OSV Cache Directory

```bash
mkdir -p .cache/osv
```

#### 2e. Run the Backend Development Server

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

The backend will be available at: `http://localhost:8000`

API documentation (auto-generated): `http://localhost:8000/docs`

Health check: `http://localhost:8000/health`

---

### Step 3: Frontend Setup

#### 3a. Install Node Dependencies

```bash
cd frontend
npm install
```

#### 3b. Configure Environment Variables

```bash
cp .env.example .env.local
# Edit .env.local: set NEXT_PUBLIC_API_URL=http://localhost:8000
```

#### 3c. Run the Frontend Development Server

```bash
npm run dev
```

The frontend will be available at: `http://localhost:3000`

> [!TIP]
> Both backend and frontend must be running simultaneously for local development. Open two terminal sessions: one for `uvicorn` and one for `npm run dev`.

---

### Step 4: Database Setup

#### 4a. Create Supabase Tables

Log in to your Supabase project, go to the SQL Editor, and run the following DDL:

```sql
-- Enable UUID generation
create extension if not exists "uuid-ossp";

-- Scans table
create table if not exists scans (
  id uuid primary key default uuid_generate_v4(),
  repo_url text not null,
  status text not null default 'PENDING',
  options jsonb default '{}',
  is_demo boolean default false,
  demo_label text,
  scenario_id text,
  created_at timestamptz not null default now(),
  completed_at timestamptz,
  error_message text,
  summary jsonb,
  gemini_summary text
);

-- Findings table
create table if not exists findings (
  id uuid primary key default uuid_generate_v4(),
  scan_id uuid not null references scans(id) on delete cascade,
  entity_id text not null,
  entity_type text not null,
  entity_name text not null,
  finding_type text not null,
  severity text not null,
  confidence float not null default 0.0,
  origin_candidate text,
  propagation_path jsonb default '[]',
  affected_assets jsonb default '[]',
  impact jsonb default '{}',
  recommendations jsonb default '[]',
  gemini_summary text,
  is_demo boolean default false,
  created_at timestamptz not null default now()
);

-- Evidence items table
create table if not exists evidence_items (
  id uuid primary key default uuid_generate_v4(),
  scan_id uuid not null references scans(id) on delete cascade,
  finding_id uuid references findings(id) on delete cascade,
  entity_id text not null,
  entity_type text not null,
  source text not null,
  evidence_type text not null,
  classification text not null,
  title text not null,
  description text not null,
  source_location jsonb,
  confidence_contribution float default 0.0,
  weight float default 0.0,
  reliability float default 1.0,
  is_simulated boolean default false,
  simulated_label text,
  raw_data jsonb default '{}',
  created_at timestamptz not null default now()
);

-- Graph snapshots table
create table if not exists graph_snapshots (
  id uuid primary key default uuid_generate_v4(),
  scan_id uuid not null references scans(id) on delete cascade,
  node_count integer not null default 0,
  edge_count integer not null default 0,
  layout_algorithm text not null default 'topological',
  graph_json jsonb not null,
  created_at timestamptz not null default now()
);

-- Indexes for common query patterns
create index if not exists idx_findings_scan_id on findings(scan_id);
create index if not exists idx_evidence_scan_id on evidence_items(scan_id);
create index if not exists idx_evidence_finding_id on evidence_items(finding_id);
create index if not exists idx_graph_scan_id on graph_snapshots(scan_id);
create index if not exists idx_scans_status on scans(status);
create index if not exists idx_scans_created_at on scans(created_at desc);

-- Row Level Security: Enable but allow service role full access
alter table scans enable row level security;
alter table findings enable row level security;
alter table evidence_items enable row level security;
alter table graph_snapshots enable row level security;

-- Policies: Allow service role full access (backend uses service role key)
create policy "service_role_all" on scans for all to service_role using (true);
create policy "service_role_all" on findings for all to service_role using (true);
create policy "service_role_all" on evidence_items for all to service_role using (true);
create policy "service_role_all" on graph_snapshots for all to service_role using (true);

-- Policies: Allow anon to read scans (for frontend polling)
create policy "anon_read_scans" on scans for select to anon using (true);
create policy "anon_read_findings" on findings for select to anon using (true);
create policy "anon_read_evidence" on evidence_items for select to anon using (true);
create policy "anon_read_graphs" on graph_snapshots for select to anon using (true);
```

#### 4b. Verify Database Setup

In the Supabase SQL Editor, run:
```sql
select table_name from information_schema.tables
where table_schema = 'public'
order by table_name;
```

Expected output: `evidence_items`, `findings`, `graph_snapshots`, `scans`.

---

### Step 5: Testing

#### 5a. Backend Tests

```bash
cd backend
pytest tests/ -v
```

Expected test suite: `tests/test_detectors.py`, `tests/test_scoring.py`, `tests/test_api.py`, `tests/test_graph.py`.

#### 5b. Frontend Tests

```bash
cd frontend
npm run test
```

#### 5c. Linting

```bash
# Backend
cd backend
flake8 app/ --max-line-length=120

# Frontend
cd frontend
npm run lint
```

#### 5d. Manual Health Checks (local)

```bash
curl http://localhost:8000/health
# Expected: {"status": "ok", "version": "1.0.0"}

curl http://localhost:8000/api/v1/health/db
# Expected: {"status": "ok", "database": "connected"}

curl http://localhost:8000/api/v1/health/osv
# Expected: {"status": "ok", "osv_api": "reachable"}
```

#### 5e. Manual Demo Scenario Test (local)

```bash
curl -X POST http://localhost:8000/api/v1/analyze/demo \
  -H "Content-Type: application/json" \
  -d '{"scenario_id": "A"}'
```

Expected: full scan result JSON with `"status": "COMPLETE"` and scenario A findings.

---

## Production Deployment

### Vercel (Frontend)

#### Step 1: Connect Repository

1. Go to [vercel.com](https://vercel.com) and log in
2. Click **Add New Project**
3. Import your GitHub repository
4. Set **Root Directory** to `frontend`
5. Framework preset: **Next.js** (auto-detected)

#### Step 2: Configure Environment Variables

In the Vercel project settings → Environment Variables, add:

| Key | Value | Environments |
|-----|-------|-------------|
| `NEXT_PUBLIC_API_URL` | `https://your-backend.onrender.com` | Production, Preview |

#### Step 3: Deploy

Click **Deploy**. Vercel will run:
1. `npm install`
2. `npm run build`
3. Deploy the `.next` output to Vercel's edge network

#### Step 4: Configure Custom Domain (optional)

Go to Vercel project → Domains → Add your custom domain and configure DNS per Vercel's instructions.

#### Step 5: Update ALLOWED_ORIGINS on Backend

After deployment, copy your Vercel deployment URL (e.g., `https://supplygraph.vercel.app`) and add it to `ALLOWED_ORIGINS` on Render.

---

### Render (Backend)

#### Step 1: Create Web Service

1. Go to [render.com](https://render.com) and log in
2. Click **New** → **Web Service**
3. Connect your GitHub repository
4. Set **Root Directory** to `backend`
5. Configure:
   - **Environment**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - **Instance Type**: At least Starter ($7/month) for persistent processes

#### Step 2: Configure Environment Variables

In the Render service settings → Environment, add all backend environment variables:

| Key | Value |
|-----|-------|
| `GITHUB_TOKEN` | `ghp_your_token` |
| `GEMINI_API_KEY` | `AIzaSy_your_key` |
| `SUPABASE_URL` | `https://your-project.supabase.co` |
| `SUPABASE_ANON_KEY` | `eyJ...` |
| `SUPABASE_SERVICE_ROLE_KEY` | `eyJ...` |
| `BACKEND_URL` | `https://your-service.onrender.com` |
| `ALLOWED_ORIGINS` | `https://your-frontend.vercel.app` |
| `OSV_CACHE_DIR` | `.cache/osv` |
| `MAX_REPO_SIZE_MB` | `100` |
| `MAX_FILES_PER_SCAN` | `1000` |
| `ANALYSIS_TIMEOUT_SECONDS` | `300` |

> [!IMPORTANT]
> On Render's free tier, services spin down after 15 minutes of inactivity. The first request after spin-down may take 30–60 seconds. For a hackathon demo, upgrade to the Starter plan to avoid this.

#### Step 3: Configure Health Check

In Render service settings → Health & Alerts:
- **Health Check Path**: `/health`
- **Health Check Interval**: 60 seconds

#### Step 4: Auto-Deploy

Enable **Auto-Deploy** from the `main` branch. Render will rebuild and redeploy on every push to `main`.

---

### Supabase

#### Step 1: Create Project

1. Go to [supabase.com](https://supabase.com)
2. Click **New Project**
3. Choose a region closest to your Render backend
4. Set a strong database password

#### Step 2: Run SQL DDL

1. Go to SQL Editor in Supabase Dashboard
2. Paste the complete DDL from Section 4a above
3. Click **Run**

#### Step 3: Configure RLS Policies

Verify that RLS policies are active by running:
```sql
select tablename, policyname, roles, cmd
from pg_policies
where schemaname = 'public'
order by tablename, policyname;
```

#### Step 4: Get Connection Details

From Supabase Dashboard → Settings → API:
- **Project URL**: copy to `SUPABASE_URL`
- **anon public key**: copy to `SUPABASE_ANON_KEY`
- **service_role key**: copy to `SUPABASE_SERVICE_ROLE_KEY`

> [!CAUTION]
> The `service_role` key bypasses RLS. Never expose it to the browser or commit it to version control.

---

## Health Checks

After deployment, verify all services are healthy:

### Backend Health Endpoints

| Endpoint | Method | Expected Response | Purpose |
|----------|--------|-----------------|---------|
| `GET /health` | GET | `{"status": "ok", "version": "1.0.0"}` | Basic liveness check |
| `GET /api/v1/health/db` | GET | `{"status": "ok", "database": "connected", "latency_ms": N}` | Database connectivity |
| `GET /api/v1/health/osv` | GET | `{"status": "ok", "osv_api": "reachable", "latency_ms": N}` | OSV API connectivity |

### Verification Commands

```bash
# Replace with your Render URL
BACKEND_URL=https://your-backend.onrender.com

curl ${BACKEND_URL}/health
curl ${BACKEND_URL}/api/v1/health/db
curl ${BACKEND_URL}/api/v1/health/osv

# Test demo endpoint
curl -X POST ${BACKEND_URL}/api/v1/analyze/demo \
  -H "Content-Type: application/json" \
  -d '{"scenario_id": "A"}' | python -m json.tool | head -50
```

### Frontend Verification

1. Open your Vercel URL in a browser
2. The dashboard should load without console errors
3. Click "Try a Demo" → select Scenario A
4. The graph and findings panel should populate

---

## Troubleshooting

| Issue | Likely Cause | Solution |
|-------|-------------|---------|
| Backend returns 500 on `/health` | Missing environment variable | Check Render env vars; look at Render logs |
| CORS errors in browser | `ALLOWED_ORIGINS` mismatch | Add your Vercel URL to `ALLOWED_ORIGINS` on Render |
| Supabase 401 errors | Wrong key used | Ensure backend uses `SUPABASE_SERVICE_ROLE_KEY`, not anon key |
| OSV queries fail | OSV API unreachable | Check network; OSV has no authentication requirement but may have rate limits |
| Render service sleeping | Free tier spin-down | Upgrade to Starter plan; or configure UptimeRobot to ping `/health` every 5 minutes |
| Graph not rendering | API URL misconfigured | Verify `NEXT_PUBLIC_API_URL` in Vercel env vars points to correct Render URL |
| GitHub API 403 | Token expired or wrong scope | Regenerate GitHub PAT with correct permissions |
| Gemini API errors | API key invalid or quota exceeded | Check key at Google AI Studio; check quota |
