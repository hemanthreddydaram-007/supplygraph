import assert from "node:assert";
import {
  parseSemVer,
  compareSemVer,
  resolveHighestSafeVersion,
  resolveVersionWithConfidence,
  getFindingPackage,
  buildLockfileSnippet,
  aggregateComponentPackages,
  detectPackageManagers,
  generateMasterAIFixPrompt,
  generateSingleAIFixPrompt,
  VERIFIED_ACTION_SHAS
} from "../lib/remediationPromptGenerator";

console.log("Starting SupplyGraph Remediation Prompt Generator Automated Test Suite...\n");

// TEST SUITE 1: SemVer Parsing & Malformed Version Constraints
console.log("Running Suite 1: SemVer & Malformed Version Constraints...");
{
  assert.strictEqual(parseSemVer(""), null, "Empty string should return null");
  assert.strictEqual(parseSemVer(null), null, "Null should return null");
  assert.strictEqual(parseSemVer("latest"), null, "'latest' should return null and never be parsed as SemVer");
  assert.strictEqual(parseSemVer("patched_version"), null, "'patched_version' placeholder should return null");
  assert.strictEqual(parseSemVer("v1.2.3")?.major, 1, "Should strip leading 'v'");
  assert.strictEqual(parseSemVer("^14.2.15")?.patch, 15, "Should strip leading '^'");
  assert.strictEqual(parseSemVer(">=0.0.18")?.minor, 0, "Should strip leading '>='");

  // Malformed PEP 440 or edge case
  const resBad = resolveVersionWithConfidence("1.0.0", ["invalid_tag", "latest", ""]);
  assert.strictEqual(resBad.category, "INVESTIGATION_REQUIRED", "Malformed candidate fixes must require investigation");
  assert(!resBad.pep440Constraint?.includes("latest"), "PEP 440 constraint must never contain 'latest'");
}

// TEST SUITE 2: Missing Fixed Versions & Unpatched Advisories
console.log("Running Suite 2: Missing Fixed Versions & Unpatched Advisories...");
{
  const resMissing = resolveVersionWithConfidence("2.3.1", []);
  assert.strictEqual(resMissing.category, "INVESTIGATION_REQUIRED");
  assert.strictEqual(resMissing.cleanVersion, "");
  assert(resMissing.explanation.includes("disputed or unpatched advisory"), "Explanation must state unpatched advisory");

  // Finding with no fixed version
  const findingNoFix = {
    id: "finding-unpatched",
    origin_candidate: "pkg:pypi/unpatched-pkg@1.0.0",
    title: "GHSA-xxxx: Unpatched zero-day in unpatched-pkg",
    severity: "HIGH",
    finding_type: "VULNERABLE",
    recommendations: [],
    evidence: []
  };
  const snippet = buildLockfileSnippet(findingNoFix);
  assert(snippet.includes("No verified upstream fixed release available"), "Snippet must explain no upstream fix exists");
  assert(!snippet.includes("latest"), "Snippet must never recommend 'latest'");
}

// TEST SUITE 3: Transitive vs. Direct Dependency Handling
console.log("Running Suite 3: Transitive vs. Direct Dependencies...");
{
  const scanWithDirectAndTransitive = {
    scan: { repository_url: "https://github.com/org/repo", lockfile_types: ["package-lock.json"] },
    components: [
      { name: "next", purl: "pkg:npm/next@14.2.15", is_direct: true, is_transitive: false, declared_in: "package.json" },
      { name: "micromatch", purl: "pkg:npm/micromatch@4.0.5", is_direct: false, is_transitive: true, declared_in: "package-lock.json" }
    ],
    findings: [
      {
        origin_candidate: "pkg:npm/next@14.2.15",
        title: "CVE-2024-1: Next.js Cache Poisoning",
        severity: "HIGH",
        finding_type: "VULNERABLE",
        recommendations: [{ fixed_version: "14.2.35" }]
      },
      {
        origin_candidate: "pkg:npm/micromatch@4.0.5",
        title: "CVE-2024-2: ReDoS in micromatch",
        severity: "MEDIUM",
        finding_type: "VULNERABLE",
        recommendations: [{ fixed_version: "4.0.8" }]
      }
    ]
  };

  const packages = aggregateComponentPackages(scanWithDirectAndTransitive);
  const nextPkg = packages.find(p => p.pkgName === "next");
  const microPkg = packages.find(p => p.pkgName === "micromatch");

  assert.strictEqual(nextPkg?.scope, "DIRECT", "next should be identified as DIRECT");
  assert.strictEqual(microPkg?.scope, "TRANSITIVE", "micromatch should be identified as TRANSITIVE");

  const prompt = generateMasterAIFixPrompt(scanWithDirectAndTransitive);
  // Direct package should be in dependencies section
  assert(prompt.includes('"next": "^14.2.35"'), "Direct package must be in dependencies");
  // Transitive package should be in overrides section
  assert(prompt.includes("Transitive Sub-Dependencies & Overrides"), "Must have overrides section");
  assert(prompt.includes('"micromatch": "^4.0.8"'), "Transitive package must be in overrides");
}

// TEST SUITE 4: Major Version Upgrade Detection & Compatibility Warning
console.log("Running Suite 4: Major Version Upgrades...");
{
  const resMajor = resolveVersionWithConfidence("1.5.0", ["2.0.1", "3.0.0"]);
  assert.strictEqual(resMajor.category, "VERIFIED_MAJOR_UPGRADE");
  assert.strictEqual(resMajor.isMajorUpgrade, true);
  assert.strictEqual(resMajor.cleanVersion, "2.0.1", "Should pick lowest safe in next major");
  assert(resMajor.explanation.includes("Major version upgrade required"), "Must warn about major upgrade");

  const scanWithMajor = {
    scan: { repository_url: "test-repo" },
    findings: [{
      origin_candidate: "pkg:npm/legacy-lib@1.0.0",
      title: "GHSA-old: Critical issue fixed only in v2",
      severity: "CRITICAL",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "2.1.0" }]
    }]
  };
  const prompt = generateMasterAIFixPrompt(scanWithMajor);
  assert(prompt.includes("[MAJOR UPGRADE REQUIRED]"), "Prompt must flag major upgrade required");
  assert(prompt.includes("Compatibility Assessment"), "Prompt must require compatibility assessment");
}

// TEST SUITE 5: GitHub Actions Pinning & SHA Integrity
console.log("Running Suite 5: GitHub Actions Pinning & SHA Integrity...");
{
  // Official verified actions
  assert(VERIFIED_ACTION_SHAS["actions/checkout"]["v4"] === "11bd71901bbe5b1630ceea73d27597364c9af683");
  assert(VERIFIED_ACTION_SHAS["actions/setup-python"]["v5"] === "42375524e23c412d93fb67b49958b491fce71c38");

  // Prompt with CI/CD code reviews
  const scanWithCicd = {
    scan: { repository_url: "ci-repo" },
    findings: [],
    code_reviews: [
      {
        title: "Unpinned GitHub Action",
        severity: "HIGH",
        file_path: ".github/workflows/deploy.yml",
        line_number: 10,
        error_explanation: "Action uses mutable tag @v4",
        unified_diff: "- uses: actions/checkout@v4\n+ uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2"
      }
    ]
  };
  const prompt = generateMasterAIFixPrompt(scanWithCicd);
  assert(prompt.includes("CI/CD Pipeline Security Hardening"), "Prompt must include CI/CD hardening");
  assert(prompt.includes("11bd71901bbe5b1630ceea73d27597364c9af683"), "Prompt must include verified SHA");
}

// TEST SUITE 6: Multi-Package Manager Detection (npm, pnpm, yarn, poetry, pipenv, uv)
console.log("Running Suite 6: Multi-Package Manager Detection...");
{
  assert.strictEqual(detectPackageManagers({ scan: { lockfile_types: ["pnpm-lock.yaml"] } }).nodePm, "pnpm");
  assert.strictEqual(detectPackageManagers({ scan: { lockfile_types: ["yarn.lock"] } }).nodePm, "yarn");
  assert.strictEqual(detectPackageManagers({ scan: { lockfile_types: ["package-lock.json"] } }).nodePm, "npm");
  assert.strictEqual(detectPackageManagers({ scan: { lockfile_types: ["poetry.lock"] } }).pythonPm, "poetry");
  assert.strictEqual(detectPackageManagers({ scan: { lockfile_types: ["uv.lock"] } }).pythonPm, "uv");
  assert.strictEqual(detectPackageManagers({ scan: { lockfile_types: ["Pipfile.lock"] } }).pythonPm, "pipenv");
  assert.strictEqual(detectPackageManagers({ scan: { lockfile_types: ["requirements.txt"] } }).pythonPm, "pip");

  // Check pnpm overrides syntax in prompt
  const pnpmScan = {
    scan: { repository_url: "pnpm-project", lockfile_types: ["pnpm-lock.yaml"] },
    findings: [{
      origin_candidate: "pkg:npm/foo@1.0.0",
      title: "GHSA-foo: Vulnerability in foo",
      severity: "HIGH",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "1.0.5" }]
    }]
  };
  const pnpmPrompt = generateMasterAIFixPrompt(pnpmScan);
  assert(pnpmPrompt.includes("pnpm.overrides"), "pnpm project prompt must use pnpm.overrides");
  assert(pnpmPrompt.includes("pnpm install"), "pnpm project prompt must use pnpm install");
}

// TEST SUITE 7: Staged 5-Phase Protocol & Section 9 Structure
console.log("Running Suite 7: 5-Phase Protocol & Section 9 Structure...");
{
  const fullScan = {
    scan: { repository_url: "https://github.com/org/fullstack", blast_radius_score: 85 },
    findings: [
      {
        origin_candidate: "pkg:npm/next@14.2.15",
        title: "CVE-2024-1234: SSRF in Next.js",
        severity: "CRITICAL",
        finding_type: "VULNERABLE",
        recommendations: [{ fixed_version: "14.2.35" }]
      },
      {
        origin_candidate: "pkg:pypi/Pillow@10.0.0",
        title: "CVE-2024-5678: Buffer Overflow in Pillow",
        severity: "HIGH",
        finding_type: "VULNERABLE",
        recommendations: [{ fixed_version: "10.4.0" }]
      }
    ]
  };
  const masterPrompt = generateMasterAIFixPrompt(fullScan);

  assert(masterPrompt.includes("PHASE A — ESTABLISH BASELINE"), "Prompt must contain Phase A");
  assert(masterPrompt.includes("PHASE B — PLAN REMEDIATION"), "Prompt must contain Phase B");
  assert(masterPrompt.includes("PHASE C — IMPLEMENT CHANGES"), "Prompt must contain Phase C");
  assert(masterPrompt.includes("PHASE D — VERIFY"), "Prompt must contain Phase D");
  assert(masterPrompt.includes("PHASE E — REPORT"), "Prompt must contain Phase E");

  // Section 9 Acceptance Criteria & Report Template
  assert(masterPrompt.includes("ACCEPTANCE CRITERIA"), "Prompt must contain Acceptance Criteria");
  assert(masterPrompt.includes("REQUIRED FINAL REMEDIATION REPORT TEMPLATE"), "Prompt must contain Report Template");
}

// TEST SUITE 8: Regression Prevention Without False Guarantees
console.log("Running Suite 8: Honest Language Without False Guarantees...");
{
  const fullScan = {
    scan: { repository_url: "health-project" },
    findings: [{
      origin_candidate: "pkg:npm/pkg@1.0.0",
      title: "Advisory",
      severity: "LOW",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "1.0.1" }]
    }]
  };
  const prompt = generateMasterAIFixPrompt(fullScan);
  assert(!prompt.toLowerCase().includes("zero regressions"), "Prompt must not make false guarantees of 'zero regressions'");
  assert(!prompt.toLowerCase().includes("100% vulnerability elimination"), "Prompt must not promise '100% vulnerability elimination'");
  assert(prompt.includes("minimizing regressions"), "Prompt must use professional 'minimizing regressions' language");
}

// TEST SUITE 9: Incomplete & Contradictory Finding Resilience
console.log("Running Suite 9: Incomplete Findings Resilience...");
{
  const incompleteScan = {
    scan: { repository_url: "broken-data-project" },
    findings: [
      { id: "null-finding", title: null, origin_candidate: null, finding_type: "VULNERABLE" },
      { id: "missing-rec", title: "Incomplete finding", origin_candidate: "pkg:unknown", finding_type: "VULNERABLE" }
    ]
  };
  // Must not throw exception
  const prompt = generateMasterAIFixPrompt(incompleteScan);
  assert(typeof prompt === "string" && prompt.length > 0, "Must generate valid string even with corrupted/incomplete data");
}

// TEST SUITE 10: Single Component Prompt Generator
console.log("Running Suite 10: Single Component Prompt Generator...");
{
  const singleFinding = {
    origin_candidate: "pkg:pypi/Pillow@10.0.0",
    title: "CVE-2023-4863: Heap Buffer Overflow in Pillow",
    severity: "CRITICAL",
    finding_type: "VULNERABLE",
    recommendations: [{ fixed_version: "10.4.0" }]
  };
  const singlePrompt = generateSingleAIFixPrompt(singleFinding, [singleFinding]);
  assert(singlePrompt.includes("AI REMEDIATION TASK: Fix Security Vulnerabilities in `Pillow`"));
  assert(singlePrompt.includes("Pillow>=10.4.0"));
  assert(singlePrompt.includes("pip install -r requirements.txt --upgrade"));
  assert(!singlePrompt.toLowerCase().includes("zero regressions"));
}

console.log("\n✅ ALL 10 TEST SUITES PASSED FLAWLESSLY!");
