# SUPPLYGRAPH HACKFUSION / YUKTHI 2026 PITCH

## THE HOOK (1 Minute)
"Hello judges, we are Team SupplyGraph. Software supply-chain attacks have grown dramatically over the past three years. The core challenge development teams face isn't a lack of vulnerability alerts—it's that when an advisory flags a compromised transitive dependency, teams lack the graph context to know whether it structurally reaches production assets or internet-facing endpoints. We built SupplyGraph to bring deterministic reachability intelligence and cryptographic integrity to supply chain security."

## THE PRODUCT (1.5 Minutes)
"SupplyGraph is an evidence-driven software supply-chain attack graph engine.
It ingests GitHub repositories or local monorepo folders, parses multi-ecosystem lockfiles (`package-lock.json`, `poetry.lock`, `requirements.txt`, `Cargo.lock`, `go.mod`) into canonical PURLs, matches vulnerabilities across ecosystems via OSV batch lookups, and runs static AST heuristics to catch suspicious behaviors like obfuscated base64 payloads and shell execution.
Instead of an unprioritized flat CVE list, we construct an inverted NetworkX dependency DAG. We calculate a bounded topological Blast Radius ($B = \min(100, 2P + 15S + 25A + 50D)$) that traces structural propagation from vulnerable packages up to internal services and production deployments for rapid triage."

## THE DEMO (1.5 Minutes)
*(Show the dashboard UI)*
"Let's look at Scenario D. We have a 4-level deep transitive dependency chain leading to 'malicious-logger'. SupplyGraph isolates the root origin and highlights the exact path.
Notice the canvas: our backend FastAPI service computes deterministic topological layers so nodes render predictably without layout jitter.
On the right, we feature dual AI intelligence powered by Google Gemini 2.5 Flash and AWS Bedrock Claude 3.5. The LLM is strictly constrained by structured graph JSON guardrails—it cannot hallucinate vulnerabilities, explaining only the verified evidence our OSV and AST detectors extracted.
And in the SBOM tab, you can export a CycloneDX 1.5 Software Bill of Materials complete with a deterministic SHA-256 posture digest staged for Polygon Amoy smart contract anchoring."

## THE ARCHITECTURE & RIGOR (1 Minute)
"Under the hood, this is a Next.js 14 frontend communicating with an asynchronous Python FastAPI backend optimized with bounded graph traversal and branch caching. Built-in demo scenarios return in under 300 milliseconds, and live repository scans complete in under 8 seconds.
Our core engine is verified by 152 automated pytest tests covering graph determinism, scoring bounds, lockfile parsers, and AST detectors.
Thank you. We are SupplyGraph, and we're ready to secure modern software supply chains."
