# SupplyGraph — 24-Hour Hackathon Priority Plan
HackFusion 2026 | Theme 6: Software Supply-Chain Attack Graph Engine

---

## TIER 1 — MUST WORK (Hours 0-14, critical path)

These items MUST be working before the hackathon ends.
No optional feature may be implemented at the expense of any Tier 1 item.

| # | Item | Est. Hours | Owner |
|---|---|---|---|
| 1 | FastAPI skeleton, health check, CORS | 0.5h | Backend Lead |
| 2 | GitHub repository ingestion (metadata + files via GitHub API) | 1.5h | Backend Lead |
| 3 | Lockfile parsers: poetry.lock, package-lock.json, requirements.txt | 2h | Backend Lead |
| 4 | PURL normalization layer | 0.5h | Backend Lead |
| 5 | CycloneDX SBOM generation | 1h | Backend Lead |
| 6 | OSV batch querying (POST /v1/querybatch) | 1h | Backend Lead |
| 7 | OSV persistent cache (.cache/osv/) | 0.5h | Backend Lead |
| 8 | NetworkX security graph construction | 1.5h | Backend Lead |
| 9 | Server-side graph layout (topological + BFS) | 1h | Backend Lead |
| 10 | Transitive path detection + affected asset model | 1h | Backend Lead |
| 11 | Heuristic confidence + blast-radius scoring | 0.5h | Backend Lead |
| 12 | Evidence model + initial containment recommendations | 0.5h | Backend Lead |
| 13 | POST /api/v1/analyze endpoint | 0.5h | Backend Lead |
| 14 | POST /api/v1/analyze/demo endpoint | 0.5h | Backend Lead |
| 15 | Deterministic demo scenario A (Vulnerable Transitive Dep) | 1h | Detection Lead |
| 16 | Deterministic demo scenario D (Multi-Level Propagation) | 1h | Detection Lead |
| 17 | Supabase schema migration (schema.sql) | 0.5h | DevOps |
| 18 | Supabase persistence for scans + findings | 1h | DevOps |
| 19 | Next.js project skeleton + Tailwind + shadcn/ui | 1h | Frontend Lead |
| 20 | API client + TypeScript graph types | 0.5h | Frontend Lead |
| 21 | React Flow graph canvas with backend positions | 1.5h | Frontend Lead |
| 22 | Analysis input form + progress display | 1h | Frontend Lead |
| 23 | Backend deployment: Render | 1h | DevOps |
| 24 | Frontend deployment: Vercel | 0.5h | DevOps |
| 25 | Public GitHub repository + README | 0.5h | DevOps |

**Tier 1 Total: ~20 hours (parallel across 3-4 team members)**

---

## TIER 2 — STRONGLY DESIRED (Hours 8-22)

Implement these after Tier 1 items are verified working.

| # | Item | Est. Hours | Dependency |
|---|---|---|---|
| 1 | Typosquatting detector | 1.5h | PURL normalization |
| 2 | Dependency confusion detector | 1h | Package metadata |
| 3 | Suspicious update detector | 1h | Version history |
| 4 | AST/static analysis engine (Python) | 2h | GitHub ingestion |
| 5 | Obfuscation detector | 0.5h | AST engine |
| 6 | Dormant logic detector | 0.5h | AST engine |
| 7 | CI/CD analysis (GitHub Actions YAML) | 1.5h | GitHub ingestion |
| 8 | Metadata anomaly detector | 1h | GitHub API |
| 9 | Evidence correlation engine | 2h | All detectors |
| 10 | Gemini explanation layer | 1h | Evidence model |
| 11 | Demo scenarios B (Typosquatting) + C (Compromised Update) + E (CI/CD) | 1.5h | Detectors |
| 12 | Security overview dashboard screen | 2h | API client |
| 13 | Findings list screen with filters | 1.5h | API client |
| 14 | Finding detail screen (full evidence view) | 1.5h | Findings API |
| 15 | Scan comparison (delta analysis) | 1.5h | Scan history |
| 16 | Attack path highlighting in graph | 1h | React Flow |

**Tier 2 Total: ~22 hours (parallel across team)**

---

## TIER 3 — OPTIONAL (Hours 20-24, only if Tier 1+2 are solid)

| # | Item |
|---|---|
| 1 | Code embeddings / semantic similarity |
| 2 | Advanced maintainer anomaly analysis |
| 3 | GitHub webhook monitoring |
| 4 | GNN-based anomaly detection |
| 5 | Advanced simulated runtime signals |
| 6 | Graph clustering / collapse UI |
| 7 | Assets inventory screen |
| 8 | Demo scenario advanced details |

---

## TEAM DIVISION

### Member 1 — Backend Lead (Security Pipeline)
- Hours 0-3: FastAPI skeleton, GitHub ingestion, lockfile parsers, PURL
- Hours 3-6: SBOM, OSV querying + cache
- Hours 6-9: NetworkX graph, layout, transitive paths
- Hours 9-12: Confidence, impact, containment, API endpoints
- Hours 12+: Detection engine support, Tier 2 backend

### Member 2 — Detection Lead
- Hours 0-2: Study detection architecture, set up Python AST
- Hours 2-5: Typosquatting detector, dependency confusion detector
- Hours 5-8: AST analysis engine, obfuscation + dormant logic
- Hours 8-11: CI/CD analysis, metadata anomaly
- Hours 11-14: Evidence correlation engine
- Hours 14+: Gemini layer, demo scenarios B/C/E

### Member 3 — Frontend Lead
- Hours 0-2: Next.js skeleton, Tailwind, shadcn/ui, API client
- Hours 2-4: TypeScript types from Pydantic models
- Hours 4-7: React Flow canvas, node rendering, edge rendering
- Hours 7-10: Analysis input + progress + security overview
- Hours 10-13: Findings list, finding detail screens
- Hours 13+: Scan comparison, attack path highlighting

### Member 4 — DevOps + QA
- Hours 0-2: Supabase schema setup, environment configuration
- Hours 2-4: Backend tests framework, integration test setup
- Hours 4-6: Backend deployment to Render
- Hours 6-8: Frontend deployment to Vercel
- Hours 8+: Testing, README, documentation, demo preparation

---

## CRITICAL PATH

```
Hour 0  → FastAPI skeleton + health check
Hour 1  → GitHub ingestion working
Hour 3  → Lockfile parsing + PURL normalization
Hour 4  → SBOM generation
Hour 5  → OSV querying
Hour 6  → NetworkX graph + layout
Hour 8  → POST /api/v1/analyze returns valid payload  ← CRITICAL GATE
Hour 9  → React Flow renders backend graph
Hour 12 → Tier 1 complete, deployment attempted
Hour 14 → Deployed and accessible  ← MINIMUM VIABLE DEMO
Hour 20 → Tier 2 features complete
Hour 22 → Demo scenarios all working
Hour 24 → Submission ready
```

---

## GOLDEN RULES

1. NEVER sacrifice Tier 1 for Tier 2 or Tier 3.
2. Deploy early (Hour 12-14). A deployed MVP beats an undeployed masterpiece.
3. Every important feature must be tested before claiming it works.
4. Use demo scenarios as fallback if real analysis fails during evaluation.
5. Keep SYSTEM_STATE.md updated after each milestone.
6. Never fabricate security findings. All evidence must be traceable.
7. Commit frequently. Push before any major change.
