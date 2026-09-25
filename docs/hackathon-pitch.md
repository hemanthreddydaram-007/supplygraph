# SUPPLYGRAPH HACKFUSION 2026 PITCH

## THE HOOK (1 Minute)
"Hello judges, we are Team SupplyGraph. Supply chain attacks have increased 742% in the last 3 years. The problem isn't that we lack vulnerability scanners. The problem is that when a scanner alerts you to a compromised transient dependency, you have no idea *how* it gets to your production environment, or *what* it can do once it gets there. We built SupplyGraph to solve exactly this."

## THE PRODUCT (1.5 Minutes)
"SupplyGraph is an evidence-driven software supply-chain attack graph engine. 
It takes a GitHub repository, parses the lockfiles into canonical purls, dynamically pulls threat intelligence from Google's OSV database, and statically analyzes the Python AST for behavioral anomalies—like obfuscated base64 payloads and reverse shells.
But instead of just handing you a list of 500 CVEs, we construct a mathematically rigorous NetworkX dependency graph. We use a proprietary heuristic engine to calculate Blast Radius and trace the exact multi-level propagation paths from the compromised dependency all the way up to your production assets."

## THE DEMO (1.5 Minutes)
*(Show the dashboard UI)*
"Let's look at Scenario D. We have a 4-level deep transitive dependency called 'malicious-logger'. SupplyGraph has flagged it in red. 
Notice the UI? We aren't guessing positions. Our backend FastAPI server runs a deterministic topological sort to position these nodes in space.
On the right, we have Google Gemini 1.5 Flash. It ingests our strict JSON attack graph and provides an explainable AI summary. We've built explicit security boundaries so Gemini *cannot* hallucinate vulnerabilities—it only explains the hard evidence our AST and OSV engines found."

## THE ARCHITECTURE & FUTURE (1 Minute)
"Under the hood, this is a Next.js frontend communicating with a heavily optimized, asynchronous Python backend using Pydantic v2 for strict type safety. It's fully containerized via Docker and ready for Kubernetes deployment. 
In the future, we plan to implement Graph Neural Networks for predictive threat modeling. 
Thank you. We are SupplyGraph, and we're ready to secure your supply chain."
