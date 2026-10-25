# 🎙️ SupplyGraph (v3.0 ASPM) — 5-Minute Master Presentation Script
## *Professional, Clean & Easy Indian English for Evaluators and General Audiences*

> **Pacing & Tone**: Speak in a calm, confident, friendly Indian English tone at approximately **125 words per minute**. Take a brief 1-second pause at each section transition. Total duration: **~5 minutes (300 seconds)**.

---

### ⏱️ SECTION 1: THE CHALLENGE IN MODERN SOFTWARE [0:00 - 0:50]
*(Screen Action: Start on Login page &rarr; Click "Judge Fast Pass" &rarr; Show main Dashboard telemetry counters)*

"Hello everyone, and respected judges! 

Today, modern applications are built using hundreds of open-source packages and dependencies across npm, Python, Go, and GitHub workflows. 

While open-source libraries help us build products faster, managing their security has become extremely complex. In large codebases, applications often contain multiple levels of nested dependencies. 

The real challenge for engineering teams is knowing: Which vulnerabilities are actually reachable and active in production code, and which ones are never called? Without this reachability context, developers can spend weeks investigating alerts or risk breaking live backend APIs during package upgrades.

That is why modern software security requires a deeper, code-aware approach."

---

### ⏱️ SECTION 2: INTRODUCING SUPPLYGRAPH [0:50 - 1:35]
*(Screen Action: Smoothly scroll down ASPM dashboard &rarr; Highlight multi-ecosystem support: npm, PyPI, Go, Actions)*

"To address this challenge, we created **SupplyGraph**.

SupplyGraph is an Application Security Posture Management platform designed to give developers complete visibility into their software supply chain.

Instead of treating dependencies as flat isolated lists, SupplyGraph analyzes your project's call paths and builds an interactive visual attack graph. It connects your code from user-facing entry points all the way down to deeply nested libraries. 

It clearly verifies whether an execution path actually reaches a vulnerable component.

When an issue is identified, SupplyGraph provides safe, line-by-line code patches that preserve application functionality, while testing untrusted packages inside an isolated sandbox."

---

### ⏱️ SECTION 3: FOUR CORE PLATFORM FEATURES [1:35 - 2:25]
*(Screen Action: Open Scenario A Attack Graph &rarr; Point to Blast Radius HUD 85/100 &rarr; Click Executive AI tab &rarr; Click CycloneDX SBOM)*

"Let us look at four core capabilities of SupplyGraph:

**First is the Attack Graph.** Powered by graph traversal algorithms, it visually maps the relationship between your application code and external libraries, showing the exact reachability path.

**Second is the Blast Radius Score.** It calculates a clear risk metric from zero to hundred, helping teams understand the potential operational impact of each finding.

**Third is the Autonomous Executive AI.** It summarizes technical vulnerability data into clear, actionable briefings and prioritized containment steps for both developers and engineering leaders.

**And fourth is the CycloneDX SBOM.** It generates standard Software Bill of Materials documents with deterministic SHA-256 cryptographic verification for compliance and governance."

---

### ⏱️ SECTION 4: FIVE PRELOADED SECURITY SCENARIOS [2:25 - 3:10]
*(Screen Action: Click through preset buttons: Scenario A &rarr; Scenario B &rarr; Scenario C &rarr; Scenario D &rarr; Scenario E)*

"To demonstrate these capabilities, SupplyGraph includes five preloaded real-world scenarios:

- **Scenario A** illustrates a transitive **Log4j** call path, mapping how an incoming request travels through service layers to a vulnerable logging library.
- **Scenario B** examines **Prototype Pollution**, showing how improper object merging can be safely identified and corrected.
- **Scenario C** analyzes insecure **Python pickle deserialization**, demonstrating AST-level detection before code execution.
- **Scenario D** audits **GitHub Actions workflows**, ensuring runners and third-party actions use immutable commit hashes.
- And **Scenario E** tests lifecycle scripts, demonstrating how package installation hooks are monitored and controlled."

---

### ⏱️ SECTION 5: REAL PROJECT DEEP DIVE (`knadh/listmonk`) [3:10 - 4:25]
*(Screen Action: In Scanner, enter `knadh/listmonk` &rarr; View benchmark & telemetry &rarr; Click "Fix with AI" &rarr; Open AI Code Reviewer &rarr; Open Detonation Sandbox)*

"Now let us examine a real-world open-source repository: **listmonk** by Kailash Nadh.

When scanning a multi-module repository like this, SupplyGraph indexes all thirty-five submodules and manifests, providing a unified inventory across frontend, backend, and workflow automation.

It identifies twenty-one findings across direct and transitive dependencies, computing a contextual Blast Radius score of sixty out of hundred.

With the **Fix with AI** feature, SupplyGraph generates evidence-based, non-breaking remediation prompts specifically structured for AI coding agents like Antigravity, Cursor, and Copilot.

In the **AI Code Reviewer**, developers can inspect surgical unified git diffs that correct the specific vulnerable lines rather than forcing broad version jumps.

And in our **Detonation Sandbox**, lifecycle scripts run within an isolated container where unauthorized network connections and file modifications are safely contained."

---

### ⏱️ SECTION 6: BLOCKCHAIN PROOF & CONCLUSION [4:25 - 5:00]
*(Screen Action: Open Polygon Amoy modal &rarr; Show transaction hash &rarr; Show final live URL and QR code)*

"Finally, every completed security audit can be cryptographically anchored to the **Polygon Amoy blockchain**, creating a tamper-evident audit trail for zero-trust compliance.

In conclusion, SupplyGraph brings together visual attack graph reachability, surgical code remediation, runtime container isolation, and verifiable supply chain integrity.

You can explore the live platform right now at **supplygraph-five.vercel.app**.

Thank you very much for your time and consideration!"
