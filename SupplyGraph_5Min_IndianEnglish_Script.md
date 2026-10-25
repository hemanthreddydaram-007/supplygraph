# 🎙️ SupplyGraph (v3.0 ASPM) — 5-Minute Master Hackathon Script
## *Easy & Simple Indian English for Evaluators and General Audiences*

> **Pacing Tip**: Speak in a calm, confident, friendly Indian English accent. Aim for **125 words per minute**. Take a brief 1-second pause at each paragraph break. Total duration: **~5 minutes (300 seconds)**.

---

### ⏱️ SECTION 1: THE PROBLEM STATEMENT [0:00 - 0:50]
*(Screen Action: Start on Login page -> Click "Judge Fast Pass" -> Show main Dashboard telemetry counters)*

"Hello everyone, and respected judges! 

Today, almost every software company uses open-source code from npm, Python, and GitHub. But here is the big problem: hackers are now hiding dangerous viruses and malware inside these small software packages.

Existing tools like GitHub Dependabot or Snyk only look at simple lists. They send hundreds of warning alerts every single day. But over ninety percent of these alerts are false alarms, because that vulnerable code is never actually used in your application!

Even worse, when developers try to blindly upgrade packages to make the warnings go away, their entire project crashes and backend APIs stop working. 

We clearly need a smarter way."

---

### ⏱️ SECTION 2: OUR PROPOSED SOLUTION — SUPPLYGRAPH [0:50 - 1:35]
*(Screen Action: Smoothly scroll down the ASPM dashboard -> Highlight multi-ecosystem support: npm, PyPI, Go, Actions)*

"To solve this real problem, we built **SupplyGraph**.

SupplyGraph is a complete Application Security Posture Management platform. 

Instead of just reading flat lists, SupplyGraph looks at your actual application code and builds an interactive visual attack graph. It connects your code from the main entrance all the way down to nested third-party packages.

SupplyGraph answers the single most important question: **'Can an attacker actually reach this bug in your running application?'**

If yes, it provides a clean, line-by-line code fix without breaking your project, and tests dangerous packages inside a secure isolated sandbox."

---

### ⏱️ SECTION 3: FOUR CORE FEATURES EXPLAINED SIMPLY [1:35 - 2:25]
*(Screen Action: Open Scenario A Attack Graph -> Point to Blast Radius HUD 85/100 -> Click Executive AI tab -> Click CycloneDX SBOM)*

"Let us look at four key features of SupplyGraph:

**First is our Attack Graph.** It maps every connection between your code and external libraries like a GPS navigation map.

**Second is the Blast Radius Score.** It gives you a simple score from zero to hundred, showing exactly how dangerous a bug is to your entire system.

**Third is our Autonomous Executive AI.** It translates complex hacker threats into plain, simple English so both managers and developers understand immediately.

**And fourth is the CycloneDX SBOM.** It generates an official digital inventory certificate of all your software parts, verified with a tamper-proof SHA-256 digital fingerprint."

---

### ⏱️ SECTION 4: FIVE REAL-WORLD ATTACK SCENARIOS [2:25 - 3:10]
*(Screen Action: Click through preset buttons: Scenario A -> Scenario B -> Scenario C -> Scenario D -> Scenario E)*

"SupplyGraph comes preloaded with five real-world attack scenarios you can test with one click:

- **Scenario A** shows the famous **Log4j** attack, tracing how hackers enter through an API and take over your server.
- **Scenario B** shows **Prototype Pollution**, where bad inputs corrupt JavaScript objects.
- **Scenario C** catches dangerous **Python pickle** files that execute hidden hacker commands.
- **Scenario D** identifies unpinned **GitHub Actions** workflows where hackers can poison your build pipeline.
- And **Scenario E** simulates a malicious **npm install** script that tries to steal secret passwords and cloud tokens."

---

### ⏱️ SECTION 5: REAL PROJECT DEEP DIVE (`knadh/listmonk`) [3:10 - 4:25]
*(Screen Action: In Scanner, enter `knadh/listmonk` -> Click "vs. Dependabot" -> Click "Fix with AI" -> Open AI Code Reviewer -> Open Detonation Sandbox)*

"Now, let us test a real-world open-source project: **listmonk** by Kailash Nadh.

When we check this repository with native GitHub Dependabot, it shows zero pull requests because it completely misses nested folders.

Now look at SupplyGraph: our scanner scans all thirty-five submodules and finds twenty-one real vulnerabilities, with an overall Blast Radius score of sixty out of hundred!

Next, look at our **Fix with AI** button. With one click, it writes a clear, evidence-based prompt for AI assistants like Antigravity, Cursor, and Copilot, telling them how to fix the code without breaking versions.

In our **AI Code Reviewer**, developers see exact green and red diff lines showing the surgical fix.

And in our **Detonation Sandbox**, when an untrusted package tries to secretly connect to a hacker server, our sandbox kills the process instantly with exit code 137."

---

### ⏱️ SECTION 6: BLOCKCHAIN PROOF & CONCLUSION [4:25 - 5:00]
*(Screen Action: Open Polygon Amoy modal -> Show transaction hash -> Show final live URL and QR code)*

"Finally, every security audit report is anchored on the **Polygon Amoy blockchain**. This creates a permanent, tamper-proof proof that nobody can fake or alter.

To conclude: SupplyGraph stops alert fatigue, prevents broken builds, isolates dangerous code, and secures modern software from start to finish.

You can try the live demo right now at **supplygraph-five.vercel.app**.

Thank you so much!"
