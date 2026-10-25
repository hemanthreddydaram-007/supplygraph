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
  VERIFIED_ACTION_SHAS,
  verifyActionSha
} from "../lib/remediationPromptGenerator";

console.log("Starting SupplyGraph Master Acceptance Test Suite (Sections 11 & 12)...\n");

// TEST 1: Complete audit with verified fixes
console.log("Running Test 1: Complete audit with verified fixes...");
{
  const scan = {
    scan: { repository_url: "https://github.com/org/verified-repo", total_findings: 2, blast_radius_score: 30 },
    components: [
      { name: "axios", purl: "pkg:npm/axios@1.6.0", is_direct: true, is_transitive: false, declared_in: "package.json" },
      { name: "requests", purl: "pkg:pypi/requests@2.31.0", is_direct: true, is_transitive: false, declared_in: "requirements.txt" }
    ],
    findings: [
      {
        id: "F1",
        origin_candidate: "pkg:npm/axios@1.6.0",
        title: "CVE-2024-1111: SSRF in axios",
        severity: "HIGH",
        finding_type: "VULNERABLE",
        recommendations: [{ fixed_version: "1.7.4" }]
      },
      {
        id: "F2",
        origin_candidate: "pkg:pypi/requests@2.31.0",
        title: "CVE-2024-2222: Proxy leakage in requests",
        severity: "MEDIUM",
        finding_type: "VULNERABLE",
        recommendations: [{ fixed_version: "2.32.3" }]
      }
    ]
  };

  const packages = aggregateComponentPackages(scan);
  const axiosPkg = packages.find(p => p.pkgName === "axios");
  const reqPkg = packages.find(p => p.pkgName === "requests");

  assert.strictEqual(axiosPkg?.resolution.category, "VERIFIED_FIXED_VERSION");
  assert.strictEqual(axiosPkg?.resolution.cleanVersion, "1.7.4");
  assert.strictEqual(reqPkg?.resolution.category, "VERIFIED_FIXED_VERSION");
  assert.strictEqual(reqPkg?.resolution.cleanVersion, "2.32.3");

  const prompt = generateMasterAIFixPrompt(scan);
  assert(prompt.includes("VERIFIED_FIXED_VERSION"));
  assert(prompt.includes('"axios": "^1.7.4"'));
  assert(prompt.includes("requests>=2.32.3"));
  assert(prompt.includes("PHASE A — ESTABLISH BASELINE"));
  assert(prompt.includes("PHASE E — REPORT"));
}

// TEST 2: Finding with no verified fixed version
console.log("Running Test 2: Finding with no verified fixed version...");
{
  const resNoFix = resolveVersionWithConfidence("1.0.0", []);
  assert.strictEqual(resNoFix.category, "NO_VERIFIED_FIX");
  assert.strictEqual(resNoFix.cleanVersion, "");
  assert(resNoFix.explanation.includes("disputed or unpatched advisory"));

  const scanNoFix = {
    scan: { repository_url: "https://github.com/org/unpatched-repo" },
    findings: [
      {
        id: "unpatched-1",
        origin_candidate: "pkg:npm/zero-day-pkg@1.0.0",
        title: "GHSA-xxxx: Zero day without upstream patch",
        severity: "CRITICAL",
        finding_type: "VULNERABLE",
        recommendations: []
      }
    ]
  };

  const prompt = generateMasterAIFixPrompt(scanNoFix);
  assert(prompt.includes("NO_VERIFIED_FIX"));
  assert(prompt.includes("Manual Investigation Required"));
  assert(!prompt.includes("latest"));
}

// TEST 3: Invalid package version recommendation
console.log("Running Test 3: Invalid package version recommendation...");
{
  assert.strictEqual(parseSemVer("latest"), null);
  assert.strictEqual(parseSemVer("patched_version"), null);
  assert.strictEqual(parseSemVer(">=latest"), null);

  const resPlaceholderOnly = resolveVersionWithConfidence("1.2.0", ["latest", "patched_version", ""]);
  assert.strictEqual(resPlaceholderOnly.category, "NO_VERIFIED_FIX");
  assert(!resPlaceholderOnly.pep440Constraint?.includes("latest"));

  const resInvalidTag = resolveVersionWithConfidence("1.2.0", ["invalid-tag"]);
  assert.strictEqual(resInvalidTag.category, "MANUAL_INVESTIGATION_REQUIRED");
  assert(resInvalidTag.explanation.includes("Manual verification needed"));

  const findingBad = {
    origin_candidate: "pkg:pypi/bad-rec@1.0.0",
    recommendations: [{ fixed_version: "latest" }]
  };
  const snippet = buildLockfileSnippet(findingBad);
  assert(!snippet.includes("latest"));
  assert(snippet.includes("No verified upstream fixed release available"));
}

// TEST 4: Major-version upgrade
console.log("Running Test 4: Major-version upgrade...");
{
  const resMajor = resolveVersionWithConfidence("12.3.0", ["13.0.0"]);
  assert.strictEqual(resMajor.category, "COMPATIBILITY_REVIEW_REQUIRED");
  assert.strictEqual(resMajor.isMajorUpgrade, true);
  assert.strictEqual(resMajor.cleanVersion, "13.0.0");
  assert(resMajor.explanation.includes("Major version upgrade required"));

  const scanMajor = {
    scan: { repository_url: "test-major" },
    findings: [{
      origin_candidate: "pkg:pypi/pillow@12.3.0",
      title: "CVE-2024-9999: Major issue",
      severity: "HIGH",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "13.0.0" }]
    }]
  };
  const prompt = generateMasterAIFixPrompt(scanMajor);
  assert(prompt.includes("COMPATIBILITY_REVIEW_REQUIRED"));
  assert(prompt.includes("[COMPATIBILITY REVIEW REQUIRED - MAJOR UPGRADE]"));
  assert(prompt.includes("Compatibility Assessment"));
}

// TEST 5: Transitive dependency vulnerability
console.log("Running Test 5: Transitive dependency vulnerability...");
{
  const scanTransitive = {
    scan: { repository_url: "transitive-repo", lockfile_types: ["package-lock.json"] },
    components: [
      { name: "express", purl: "pkg:npm/express@4.18.2", is_direct: true, is_transitive: false, declared_in: "package.json" },
      { name: "qs", purl: "pkg:npm/qs@6.11.0", is_direct: false, is_transitive: true, declared_in: "package-lock.json" }
    ],
    findings: [
      {
        origin_candidate: "pkg:npm/express@4.18.2",
        title: "CVE-2024-express: Express patch",
        severity: "LOW",
        finding_type: "VULNERABLE",
        recommendations: [{ fixed_version: "4.19.2" }]
      },
      {
        origin_candidate: "pkg:npm/qs@6.11.0",
        title: "CVE-2024-qs: Prototype pollution in qs",
        severity: "HIGH",
        finding_type: "VULNERABLE",
        recommendations: [{ fixed_version: "6.11.2" }]
      }
    ]
  };

  const pkgs = aggregateComponentPackages(scanTransitive);
  assert.strictEqual(pkgs.find(p => p.pkgName === "express")?.scope, "DIRECT");
  assert.strictEqual(pkgs.find(p => p.pkgName === "qs")?.scope, "TRANSITIVE");

  const prompt = generateMasterAIFixPrompt(scanTransitive);
  assert(prompt.includes('"express": "^4.19.2"'));
  assert(prompt.includes('"qs": "^6.11.2"'));
  assert(prompt.includes("Transitive Sub-Dependencies & Overrides"));
  assert(prompt.includes("Do NOT add transitive dependencies into root `dependencies`"));
}

// TEST 6: npm workspace with multiple manifests
console.log("Running Test 6: npm workspace with multiple manifests...");
{
  const scanWorkspace = {
    scan: { repository_url: "workspace-repo", lockfile_types: ["package-lock.json"] },
    files: [
      { path: "package.json" },
      { path: "packages/frontend/package.json" },
      { path: "packages/backend/package.json" }
    ],
    findings: [{
      origin_candidate: "pkg:npm/lodash@4.17.20",
      title: "CVE-2021-23337: Prototype Pollution in lodash",
      severity: "HIGH",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "4.17.21" }]
    }]
  };

  const pm = detectPackageManagers(scanWorkspace);
  assert.strictEqual(pm.workspaces.isWorkspace, true);
  assert.strictEqual(pm.workspaces.manifests.length, 3);

  const prompt = generateMasterAIFixPrompt(scanWorkspace);
  assert(prompt.includes("Monorepo / Multi-Manifest Workspace Detected"));
  assert(prompt.includes("packages/frontend/package.json"));
  assert(prompt.includes("packages/backend/package.json"));
}

// TEST 7: Python project with a lockfile (poetry, uv, pipenv)
console.log("Running Test 7: Python project with a lockfile...");
{
  const poetryScan = {
    scan: { repository_url: "poetry-repo", lockfile_types: ["poetry.lock"] },
    findings: [{
      origin_candidate: "pkg:pypi/jinja2@3.1.2",
      title: "CVE-2024-34064: HTML injection in Jinja2",
      severity: "HIGH",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "3.1.4" }]
    }]
  };
  const poetryPm = detectPackageManagers(poetryScan);
  assert.strictEqual(poetryPm.pythonPm, "poetry");
  const poetryPrompt = generateMasterAIFixPrompt(poetryScan);
  assert(poetryPrompt.includes("poetry lock --no-update && poetry install"));

  const uvScan = {
    scan: { repository_url: "uv-repo", lockfile_types: ["uv.lock"] },
    findings: [{
      origin_candidate: "pkg:pypi/jinja2@3.1.2",
      title: "CVE-2024-34064: HTML injection in Jinja2",
      severity: "HIGH",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "3.1.4" }]
    }]
  };
  assert.strictEqual(detectPackageManagers(uvScan).pythonPm, "uv");
  const uvPrompt = generateMasterAIFixPrompt(uvScan);
  assert(uvPrompt.includes("uv lock && uv sync"));
}

// TEST 8: Project using pip without a lockfile
console.log("Running Test 8: Project using pip without a lockfile...");
{
  const pipScan = {
    scan: { repository_url: "pip-repo", lockfile_types: ["requirements.txt"] },
    findings: [{
      origin_candidate: "pkg:pypi/flask@2.2.0",
      title: "CVE-2023-1234: Denial of service in flask",
      severity: "MEDIUM",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "2.2.5" }]
    }]
  };
  const pipPm = detectPackageManagers(pipScan);
  assert.strictEqual(pipPm.pythonPm, "pip");
  const pipPrompt = generateMasterAIFixPrompt(pipScan);
  assert(pipPrompt.includes("pip install -r requirements.txt --upgrade"));
  assert(pipPrompt.includes("Never assume that `pip install` automatically regenerates a lockfile"));
}

// TEST 9: GitHub Actions Pinning & SHA Integrity
console.log("Running Test 9: GitHub Actions Pinning & SHA Integrity...");
{
  assert.strictEqual(VERIFIED_ACTION_SHAS["actions/checkout"]["v4"], "11bd71901bbe5b1630ceea73d27597364c9af683");
  assert.strictEqual(VERIFIED_ACTION_SHAS["docker/login-action"]["v3"], "9780b0c442fbb1117ed29e0efdff1e18412f7567");

  const scanCicd = {
    scan: { repository_url: "ci-repo" },
    findings: [],
    code_reviews: [{
      title: "Unpinned GitHub Action",
      severity: "HIGH",
      file_path: ".github/workflows/ci.yml",
      line_number: 14,
      error_explanation: "Action pinned to mutable @v4 tag",
      unified_diff: "- uses: actions/checkout@v4\n+ uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2"
    }]
  };
  const prompt = generateMasterAIFixPrompt(scanCicd);
  assert(prompt.includes("11bd71901bbe5b1630ceea73d27597364c9af683"));
  assert(prompt.includes(".github/workflows/ci.yml"));
}

// TEST 10: Duplicate advisory findings
console.log("Running Test 10: Duplicate advisory findings...");
{
  const scanDuplicates = {
    scan: { repository_url: "dup-repo", total_findings: 3 },
    findings: [
      {
        id: "F1",
        origin_candidate: "pkg:npm/tar@6.1.0",
        title: "CVE-2021-37712: Symlink path traversal in tar",
        severity: "HIGH",
        finding_type: "VULNERABLE",
        recommendations: [{ fixed_version: "6.1.11" }]
      },
      {
        id: "F2",
        origin_candidate: "pkg:npm/tar@6.1.0",
        title: "CVE-2021-37712: Symlink path traversal in tar (duplicate entry)",
        severity: "HIGH",
        finding_type: "VULNERABLE",
        recommendations: [{ fixed_version: "6.1.11" }]
      },
      {
        id: "F3",
        origin_candidate: "pkg:npm/tar@6.1.0",
        title: "CVE-2021-37713: Arbitrary File Overwrite in tar",
        severity: "HIGH",
        finding_type: "VULNERABLE",
        recommendations: [{ fixed_version: "6.1.11" }]
      }
    ]
  };

  const pkgs = aggregateComponentPackages(scanDuplicates);
  const tarPkg = pkgs.find(p => p.pkgName === "tar");
  assert.strictEqual(tarPkg?.findings.length, 3, "Raw finding count must be preserved as 3");
  assert.strictEqual(tarPkg?.advisories.length, 2, "Unique advisories must be deduplicated to 2");

  const prompt = generateMasterAIFixPrompt(scanDuplicates);
  assert(prompt.includes("Total Raw Security Findings Reported**: 3"));
  assert(prompt.includes("Unique Security Advisories (CVE / GHSA / OSV)**: 2"));
  assert(prompt.includes("Unique Affected Packages / Components**: 1"));
  assert(prompt.includes("INVENTORY COUNTING RULE"));
}

// TEST 11: Missing manifest paths
console.log("Running Test 11: Missing manifest paths...");
{
  const scanMissingManifest = {
    scan: { repository_url: "no-manifest-repo" },
    findings: [{
      origin_candidate: "pkg:pypi/unmapped-lib@1.0.0",
      title: "CVE-2024-0001: Missing manifest link",
      severity: "MEDIUM",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "1.0.2" }]
    }]
  };
  const prompt = generateMasterAIFixPrompt(scanMissingManifest);
  assert(prompt.includes("Target File(s)"));
  assert(prompt.includes("unmapped-lib>=1.0.2"));
}

// TEST 12: Conflicting findings / multiple scanner results
console.log("Running Test 12: Conflicting findings...");
{
  const scanConflict = {
    scan: { repository_url: "conflict-repo" },
    findings: [
      {
        id: "OSV-1",
        origin_candidate: "pkg:npm/debug@4.1.0",
        title: "OSV finding recommending 4.1.1",
        severity: "LOW",
        finding_type: "VULNERABLE",
        recommendations: [{ fixed_version: "4.1.1" }]
      },
      {
        id: "NVD-1",
        origin_candidate: "pkg:npm/debug@4.1.0",
        title: "NVD finding recommending 4.3.4",
        severity: "HIGH",
        finding_type: "VULNERABLE",
        recommendations: [{ fixed_version: "4.3.4" }]
      }
    ]
  };
  const pkgs = aggregateComponentPackages(scanConflict);
  const debugPkg = pkgs.find(p => p.pkgName === "debug");
  assert.strictEqual(debugPkg?.resolution.cleanVersion, "4.3.4", "Should pick highest safe patch in same major");
  assert.strictEqual(debugPkg?.highestSeverity, "HIGH", "Should adopt highest severity");
}

// TEST 13: Scanner reporting zero CI/CD findings
console.log("Running Test 13: Scanner reporting zero CI/CD findings...");
{
  const scanCleanCicd = {
    scan: { repository_url: "clean-ci-repo" },
    findings: [{
      origin_candidate: "pkg:npm/react@18.2.0",
      title: "Advisory",
      severity: "LOW",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "18.3.1" }]
    }],
    code_reviews: []
  };
  const prompt = generateMasterAIFixPrompt(scanCleanCicd);
  assert(prompt.includes("Scope of performed CI/CD checks"));
  assert(prompt.includes("0 actionable risks detected across audited workflow files"));
  assert(prompt.includes("This audit evaluates static workflow configurations"));
  assert(!prompt.includes("All CI/CD workflows comply with OpenSSF"));
}

// TEST 14: Post-remediation scan with unresolved vulnerabilities
console.log("Running Test 14: Post-remediation scan with unresolved vulnerabilities...");
{
  const scanWithResidual = {
    scan: { repository_url: "residual-repo" },
    findings: [{
      origin_candidate: "pkg:pypi/unfixable@0.1.0",
      title: "Zero-day vulnerability",
      severity: "HIGH",
      finding_type: "VULNERABLE",
      recommendations: []
    }]
  };
  const prompt = generateMasterAIFixPrompt(scanWithResidual);
  assert(prompt.includes("REQUIRED FINAL REMEDIATION REPORT TEMPLATE (PHASE E)"));
  assert(prompt.includes("Findings Requiring Manual Review"));
  assert(prompt.includes("Remaining Limitations & Residual Risks"));
  assert(prompt.includes("NEVER claim a command succeeded unless executed"));
}

// TEST 15 (Section 12 Reference Scenario): kisan-ai-core (55 findings across 5 packages)
console.log("Running Test 15: Reference Scenario (kisan-ai-core - 55 findings)...");
{
  // 55 findings: 13 Node.js findings + 42 Python findings
  const mockFindings: any[] = [];

  // Next.js: 6 findings
  for (let i = 1; i <= 6; i++) {
    mockFindings.push({
      id: `NEXT-${i}`,
      origin_candidate: "pkg:npm/next@16.3.3",
      title: `GHSA-next-${i}: SSRF and cache issue in Next.js`,
      severity: i === 1 ? "CRITICAL" : "HIGH",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "16.4.1" }]
    });
  }

  // sharp: 4 findings
  for (let i = 1; i <= 4; i++) {
    mockFindings.push({
      id: `SHARP-${i}`,
      origin_candidate: "pkg:npm/sharp@0.35.4",
      title: `GHSA-sharp-${i}: Memory leak in sharp`,
      severity: "MEDIUM",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "0.35.5" }]
    });
  }

  // source-map-js: 3 findings (transitive)
  for (let i = 1; i <= 3; i++) {
    mockFindings.push({
      id: `SM-${i}`,
      origin_candidate: "pkg:npm/source-map-js@1.2.1",
      title: `GHSA-sm-${i}: ReDoS in source-map-js`,
      severity: "LOW",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "1.2.2" }]
    });
  }

  // python-dotenv: 10 findings
  for (let i = 1; i <= 10; i++) {
    mockFindings.push({
      id: `DOTENV-${i}`,
      origin_candidate: "pkg:pypi/python-dotenv@1.0.1",
      title: `CVE-dotenv-${i}: Environment parsing issue`,
      severity: "MEDIUM",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "1.2.2" }]
    });
  }

  // pillow: 32 findings (crossing major version 12.3.0 -> 13.0.0)
  for (let i = 1; i <= 32; i++) {
    mockFindings.push({
      id: `PILLOW-${i}`,
      origin_candidate: "pkg:pypi/pillow@12.3.0",
      title: `CVE-pillow-${i}: Buffer overflow in Pillow`,
      severity: i <= 5 ? "CRITICAL" : "HIGH",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "13.0.0" }]
    });
  }

  assert.strictEqual(mockFindings.length, 55, "Total raw findings must be exactly 55");

  const kisanScan = {
    scan: {
      repository_url: "https://github.com/hemanthreddydaram-007/kisan-ai-core",
      total_findings: 55,
      blast_radius_score: 92,
      lockfile_types: ["package.json", "package-lock.json", "requirements.txt"]
    },
    components: [
      { name: "next", purl: "pkg:npm/next@16.3.3", is_direct: true, is_transitive: false, declared_in: "package.json" },
      { name: "sharp", purl: "pkg:npm/sharp@0.35.4", is_direct: true, is_transitive: false, declared_in: "package.json" },
      { name: "source-map-js", purl: "pkg:npm/source-map-js@1.2.1", is_direct: false, is_transitive: true, declared_in: "package-lock.json" },
      { name: "python-dotenv", purl: "pkg:pypi/python-dotenv@1.0.1", is_direct: true, is_transitive: false, declared_in: "requirements.txt" },
      { name: "pillow", purl: "pkg:pypi/pillow@12.3.0", is_direct: true, is_transitive: false, declared_in: "requirements.txt" }
    ],
    findings: mockFindings
  };

  const pkgs = aggregateComponentPackages(kisanScan);
  assert.strictEqual(pkgs.length, 5, "Must group 55 findings into exactly 5 unique components");

  const nextPkg = pkgs.find(p => p.pkgName === "next");
  const sharpPkg = pkgs.find(p => p.pkgName === "sharp");
  const smPkg = pkgs.find(p => p.pkgName === "source-map-js");
  const dotenvPkg = pkgs.find(p => p.pkgName === "python-dotenv");
  const pillowPkg = pkgs.find(p => p.pkgName === "pillow");

  assert.strictEqual(nextPkg?.resolution.cleanVersion, "16.4.1");
  assert.strictEqual(nextPkg?.resolution.category, "VERIFIED_FIXED_VERSION");

  assert.strictEqual(sharpPkg?.resolution.cleanVersion, "0.35.5");
  assert.strictEqual(sharpPkg?.resolution.category, "VERIFIED_FIXED_VERSION");

  assert.strictEqual(smPkg?.resolution.cleanVersion, "1.2.2");
  assert.strictEqual(smPkg?.resolution.category, "VERIFIED_FIXED_VERSION");
  assert.strictEqual(smPkg?.scope, "TRANSITIVE");

  assert.strictEqual(dotenvPkg?.resolution.cleanVersion, "1.2.2");
  assert.strictEqual(dotenvPkg?.resolution.category, "VERIFIED_FIXED_VERSION");
  assert.strictEqual(dotenvPkg?.resolution.pep440Constraint, ">=1.2.2");

  // Pillow is a major upgrade (12.3.0 -> 13.0.0)
  assert.strictEqual(pillowPkg?.resolution.cleanVersion, "13.0.0");
  assert.strictEqual(pillowPkg?.resolution.category, "COMPATIBILITY_REVIEW_REQUIRED");
  assert.strictEqual(pillowPkg?.resolution.isMajorUpgrade, true);
  assert.strictEqual(pillowPkg?.resolution.pep440Constraint, ">=13.0.0");

  const prompt = generateMasterAIFixPrompt(kisanScan);

  // Verification assertions for Reference Scenario
  assert(prompt.includes("Total Raw Security Findings Reported**: 55"));
  assert(prompt.includes("Unique Affected Packages / Components**: 5"));
  assert(prompt.includes("INVENTORY COUNTING RULE"));
  assert(prompt.includes('"next": "^16.4.1"'));
  assert(prompt.includes('"sharp": "^0.35.5"'));
  assert(prompt.includes('"source-map-js": "^1.2.2"'));
  assert(prompt.includes("python-dotenv>=1.2.2"));
  assert(prompt.includes("pillow>=13.0.0"));
  assert(prompt.includes("COMPATIBILITY_REVIEW_REQUIRED"));
  assert(prompt.includes("Original Raw Finding Count**: 55"));
  assert(prompt.includes("Do NOT promise \"zero regressions\""));
  assert(prompt.includes("minimizing regressions"));
}

// TEST 16: Backend Source Code Patches & Call-Site Audit Verification
console.log("Running Test 16: Backend Code Patches & Call-Site Audit Verification...");
{
  const scanWithCodeReviews = {
    scan: { repository_url: "https://github.com/org/fullstack-app" },
    findings: [],
    code_reviews: [
      {
        id: "CR-1",
        title: "Remote Code Execution via Insecure pickle.loads()",
        severity: "CRITICAL",
        category: "Security Vulnerability",
        file_path: "backend/data_loader.py",
        line_number: 48,
        error_explanation: "Using pickle.loads() on network input allows remote code execution.",
        buggy_code: "user_obj = pickle.loads(raw_payload)",
        corrected_code: "user_obj = json.loads(raw_payload.decode('utf-8'))"
      },
      {
        id: "CR-2",
        title: "Cross-Site Scripting (XSS) via dangerouslySetInnerHTML",
        severity: "HIGH",
        category: "Security Vulnerability",
        file_path: "src/components/UserProfile.tsx",
        line_number: 31,
        error_explanation: "Rendering unescaped user bio allows script injection.",
        buggy_code: "<div dangerouslySetInnerHTML={{ __html: user.bio }} />",
        corrected_code: "<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(user.bio) }} />"
      },
      {
        id: "CR-3",
        title: "Unpinned GitHub Action in Deployment Workflow",
        severity: "HIGH",
        category: "CI/CD Security",
        file_path: ".github/workflows/deploy.yml",
        line_number: 19,
        error_explanation: "Action references mutable @v2 branch tag.",
        buggy_code: "uses: actions/upload-artifact@v2",
        corrected_code: "uses: actions/upload-artifact@4cec3d8aa04e39d1a68397de0c4cd6fb99ba5ed1 # v4.1.4"
      }
    ]
  };

  const prompt = generateMasterAIFixPrompt(scanWithCodeReviews);

  // Must separate Backend Code Fixes from CI/CD Workflow Fixes
  assert(prompt.includes("Backend & Application Source Code Vulnerability Fixes (AST & Static Code Review)"));
  assert(prompt.includes("backend/data_loader.py"));
  assert(prompt.includes("```python\nuser_obj = pickle.loads(raw_payload)"));
  assert(!prompt.includes("```yaml\nuser_obj = pickle.loads(raw_payload)")); // Must NOT use yaml for Python!

  assert(prompt.includes("src/components/UserProfile.tsx"));
  assert(prompt.includes("```typescript\n<div dangerouslySetInnerHTML"));

  // CI/CD section must contain workflow items
  assert(prompt.includes(".github/workflows/deploy.yml"));
  assert(prompt.includes("```yaml\nuses: actions/upload-artifact@v2"));

  // Must include Call-Site Dependency Audit and Backend Integrity Smoke Tests
  assert(prompt.includes("Call-Site Dependency Audit & API Compatibility Refactoring"));
  assert(prompt.includes("WHY BACKENDS BREAK ON DEPENDENCY UPDATES"));
  assert(prompt.includes("python -m py_compile"));
  assert(prompt.includes("python -c \"import <main_entrypoint>\""));
}

console.log("\n🎯 BASELINE 16 ACCEPTANCE SUITES PASSED! Now executing Master Engineering Directive Test Groups A-E...\n");

// =========================================================================
// TEST GROUP A: ADVISORY EVIDENCE (7 TESTS)
// =========================================================================
console.log("--- TEST GROUP A: ADVISORY EVIDENCE ---");

// A.1: Verified fixed version supported by evidence
console.log("Running Test A.1: Verified fixed version supported by evidence...");
{
  const res = resolveVersionWithConfidence("1.2.0", ["1.4.0"]);
  assert.strictEqual(res.category, "VERIFIED_FIXED_VERSION");
  assert.strictEqual(res.cleanVersion, "1.4.0");
  assert.strictEqual(res.isMajorUpgrade, false);

  const scan = {
    scan: { repository_url: "https://github.com/test-org/repo-a1" },
    findings: [{
      origin_candidate: "pkg:npm/safe-lib@1.2.0",
      title: "CVE-2024-0010: Fix in 1.4.0",
      severity: "MEDIUM",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "1.4.0" }]
    }]
  };
  const prompt = generateMasterAIFixPrompt(scan);
  assert(prompt.includes("VERIFIED_FIXED_VERSION"));
  assert(prompt.includes('"safe-lib": "^1.4.0"'));
  assert(!prompt.includes("[COMPATIBILITY REVIEW REQUIRED - MAJOR UPGRADE]"));
}

// A.2: Newer version without verified fix evidence
console.log("Running Test A.2: Newer version without verified fix evidence...");
{
  const resLatest = resolveVersionWithConfidence("1.2.0", ["latest"]);
  assert.strictEqual(resLatest.category, "NO_VERIFIED_FIX");
  assert.strictEqual(resLatest.cleanVersion, "");

  const resPlaceholder = resolveVersionWithConfidence("1.2.0", ["patched_version"]);
  assert.strictEqual(resPlaceholder.category, "NO_VERIFIED_FIX");

  const scan = {
    scan: { repository_url: "https://github.com/test-org/repo-a2" },
    findings: [{
      origin_candidate: "pkg:pypi/unverified-lib@1.2.0",
      title: "GHSA-unverified: No verified fix",
      severity: "HIGH",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "latest" }]
    }]
  };
  const prompt = generateMasterAIFixPrompt(scan);
  assert(prompt.includes("NO_VERIFIED_FIX"));
  assert(!prompt.includes("unverified-lib>=latest"));
  assert(prompt.includes("Manual Investigation Required"));
}

// A.3: Multiple advisories requiring different fixed versions
console.log("Running Test A.3: Multiple advisories requiring different fixed versions...");
{
  // Advisory 1 requires >= 1.4.0 (same major), but Advisory 2 requires >= 2.0.0 (major upgrade).
  // The candidate satisfying ALL advisories must be 2.0.0, NOT 1.4.0 (which leaves Adv 2 unpatched!).
  const scanMultiAdv = {
    scan: { repository_url: "https://github.com/test-org/repo-a3" },
    findings: [
      {
        id: "F-ADV-1",
        origin_candidate: "pkg:npm/multi-adv-pkg@1.2.0",
        title: "CVE-2024-1001: Adv 1 fixed in 1.4.0",
        severity: "MEDIUM",
        finding_type: "VULNERABLE",
        recommendations: [{ fixed_version: "1.4.0" }]
      },
      {
        id: "F-ADV-2",
        origin_candidate: "pkg:npm/multi-adv-pkg@1.2.0",
        title: "CVE-2024-2002: Adv 2 fixed in 2.0.0",
        severity: "CRITICAL",
        finding_type: "VULNERABLE",
        recommendations: [{ fixed_version: "2.0.0" }]
      }
    ]
  };

  const pkgs = aggregateComponentPackages(scanMultiAdv);
  const pkg = pkgs.find(p => p.pkgName === "multi-adv-pkg");
  assert(pkg, "Package must be aggregated");
  assert.strictEqual(pkg.resolution.cleanVersion, "2.0.0", "Candidate must be 2.0.0 to satisfy all advisories");
  assert.strictEqual(pkg.resolution.category, "COMPATIBILITY_REVIEW_REQUIRED", "Must be flagged for compatibility review");
  assert.strictEqual(pkg.resolution.isMajorUpgrade, true);

  const prompt = generateMasterAIFixPrompt(scanMultiAdv);
  assert(prompt.includes("COMPATIBILITY_REVIEW_REQUIRED"));
  assert(prompt.includes('"multi-adv-pkg": "^2.0.0"'));
  assert(prompt.includes("Major version upgrade required (1.x -> 2.x) to satisfy all advisories"));
}

// A.4: No published fix
console.log("Running Test A.4: No published fix...");
{
  const resNoFix = resolveVersionWithConfidence("1.0.0", []);
  assert.strictEqual(resNoFix.category, "NO_VERIFIED_FIX");
  assert(resNoFix.explanation.includes("unpatched"));

  const scanNoFix = {
    scan: { repository_url: "https://github.com/test-org/repo-a4" },
    findings: [{
      origin_candidate: "pkg:pypi/zero-day@1.0.0",
      title: "CVE-2024-9999: Zero-day without upstream release",
      severity: "CRITICAL",
      finding_type: "VULNERABLE",
      recommendations: []
    }]
  };
  const prompt = generateMasterAIFixPrompt(scanNoFix);
  assert(prompt.includes("NO_VERIFIED_FIX"));
  assert(prompt.includes("Advisories Requiring Manual Investigation (No Verified Upstream Release)"));
  assert(prompt.includes("zero-day@1.0.0"));
}

// A.5: External advisory source unavailable
console.log("Running Test A.5: External advisory source unavailable...");
{
  const resUnavailable = resolveVersionWithConfidence("1.0.0", ["1.2.0"], { sourceUnavailable: true });
  assert.strictEqual(resUnavailable.category, "MANUAL_INVESTIGATION_REQUIRED");
  assert(resUnavailable.explanation.includes("Authoritative external advisory source was unavailable"));
}

// A.6: Conflicting upstream evidence
console.log("Running Test A.6: Conflicting upstream evidence...");
{
  const resConflict = resolveVersionWithConfidence("1.0.0", ["1.2.0"], { conflictingSources: true });
  assert.strictEqual(resConflict.category, "MANUAL_INVESTIGATION_REQUIRED");
  assert(resConflict.explanation.includes("Conflicting upstream advisory evidence detected"));
}

// A.7: Major upgrade requiring compatibility review
console.log("Running Test A.7: Major upgrade requiring compatibility review...");
{
  const resMajor = resolveVersionWithConfidence("1.5.0", ["2.0.0"]);
  assert.strictEqual(resMajor.category, "COMPATIBILITY_REVIEW_REQUIRED");
  assert.strictEqual(resMajor.isMajorUpgrade, true);
  assert.strictEqual(resMajor.majorDiff, 1);
  assert.strictEqual(resMajor.cleanVersion, "2.0.0");
}

// =========================================================================
// TEST GROUP B: MODIFICATION SCOPE (4 TESTS)
// =========================================================================
console.log("\n--- TEST GROUP B: MODIFICATION SCOPE ---");

// B.1: Normal manifest and lockfile remediation (Category A)
console.log("Running Test B.1: Normal manifest and lockfile remediation (Category A)...");
{
  const scanB1 = {
    scan: { repository_url: "https://github.com/test-org/repo-b1" },
    findings: [{
      origin_candidate: "pkg:npm/lodash@4.17.20",
      title: "CVE-2021-23337: Command injection in lodash",
      severity: "HIGH",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "4.17.21" }]
    }]
  };
  const prompt = generateMasterAIFixPrompt(scanB1);
  assert(prompt.includes("Structured 3-Tier Modification Scope Policy"));
  assert(prompt.includes("Category A — Expected Remediation Files"));
  assert(prompt.includes("package.json"));
  assert(prompt.includes("package-lock.json"));
}

// B.2: Verified upgrade requiring a source-code compatibility change (Category B)
console.log("Running Test B.2: Verified upgrade requiring a source-code compatibility change (Category B)...");
{
  const scanB2 = {
    scan: { repository_url: "https://github.com/test-org/repo-b2" },
    findings: [{
      origin_candidate: "pkg:pypi/pillow@9.5.0",
      title: "CVE-2023-44271: Buffer overflow in Pillow",
      severity: "HIGH",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "10.0.1" }]
    }]
  };
  const prompt = generateMasterAIFixPrompt(scanB2);
  assert(prompt.includes("Category B — Necessary Compatibility Files (Call-Sites)"));
  assert(prompt.includes("PERMITTED ONLY when strictly necessary"));
  assert(prompt.includes("MUST document every modified Category B file"));
  assert(prompt.includes("Image.ANTIALIAS"));
  assert(prompt.includes("Image.Resampling.LANCZOS"));
}

// B.3: Necessary additional file discovered during remediation
console.log("Running Test B.3: Necessary additional file discovered during remediation...");
{
  const scanB3 = {
    scan: { repository_url: "https://github.com/test-org/repo-b3" },
    findings: [{
      origin_candidate: "pkg:pypi/pydantic@1.10.8",
      title: "CVE-2023-xxxx: DoS in Pydantic",
      severity: "MEDIUM",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "2.5.0" }]
    }]
  };
  const prompt = generateMasterAIFixPrompt(scanB3);
  assert(prompt.includes("EXECUTION RULES FOR CATEGORY B MODIFICATIONS"));
  assert(prompt.includes("extend scope narrowly and document the reason"));
  assert(prompt.includes("from pydantic_settings import BaseSettings"));
}

// B.4: Unrelated file proposed for modification (Category C prohibited)
console.log("Running Test B.4: Unrelated file proposed for modification (Category C prohibited)...");
{
  const scanB4 = {
    scan: { repository_url: "https://github.com/test-org/repo-b4" },
    findings: []
  };
  const prompt = generateMasterAIFixPrompt(scanB4);
  assert(prompt.includes("Category C — Unrelated Project Files (STRICTLY PROHIBITED)"));
  assert(prompt.includes("**Category C (Prohibited Files Touched)**: None (0 files touched)"));
  assert(prompt.includes("Modification of Category C files is strictly prohibited"));
}

// =========================================================================
// TEST GROUP C: PACKAGE-MANAGER BEHAVIOR (8 TESTS)
// =========================================================================
console.log("\n--- TEST GROUP C: PACKAGE-MANAGER BEHAVIOR ---");

// C.1: npm with package-lock
console.log("Running Test C.1: npm with package-lock...");
{
  const scanC1 = {
    scan: { repository_url: "npm-repo", lockfile_types: ["package-lock.json"] },
    findings: [{
      origin_candidate: "pkg:npm/cookie@0.4.0",
      title: "CVE-2024-xxxx: cookie issue",
      severity: "LOW",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "0.4.2" }]
    }]
  };
  const pm = detectPackageManagers(scanC1);
  assert.strictEqual(pm.nodePm, "npm");
  const prompt = generateMasterAIFixPrompt(scanC1);
  assert(prompt.includes("Targeted lockfile update for npm"));
  assert(prompt.includes("npm install cookie@0.4.2 --package-lock-only"));
}

// C.2: pnpm with workspace lockfile
console.log("Running Test C.2: pnpm with workspace lockfile...");
{
  const scanC2 = {
    scan: { repository_url: "pnpm-repo", lockfile_types: ["pnpm-lock.yaml"] },
    files: [{ path: "pnpm-lock.yaml" }, { path: "package.json" }],
    findings: [{
      origin_candidate: "pkg:npm/minimatch@3.0.4",
      title: "CVE-2022-3517: ReDoS in minimatch",
      severity: "HIGH",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "3.0.8" }]
    }]
  };
  const pm = detectPackageManagers(scanC2);
  assert.strictEqual(pm.nodePm, "pnpm");
  const prompt = generateMasterAIFixPrompt(scanC2);
  assert(prompt.includes("pnpm.overrides"));
  assert(prompt.includes("pnpm update minimatch@3.0.8"));
}

// C.3: Yarn with detected version
console.log("Running Test C.3: Yarn with detected version...");
{
  const scanC3 = {
    scan: { repository_url: "yarn-repo", lockfile_types: ["yarn.lock"] },
    files: [{ path: "yarn.lock" }, { path: "package.json" }],
    findings: [{
      origin_candidate: "pkg:npm/ws@7.4.0",
      title: "CVE-2021-32640: ReDoS in ws",
      severity: "HIGH",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "7.5.9" }]
    }]
  };
  const pm = detectPackageManagers(scanC3);
  assert.strictEqual(pm.nodePm, "yarn");
  const prompt = generateMasterAIFixPrompt(scanC3);
  assert(prompt.includes('"resolutions"'));
  assert(prompt.includes("yarn up ws@7.5.9"));
}

// C.4: Poetry with poetry.lock
console.log("Running Test C.4: Poetry with poetry.lock...");
{
  const scanC4 = {
    scan: { repository_url: "poetry-repo", lockfile_types: ["poetry.lock"] },
    files: [{ path: "poetry.lock" }, { path: "pyproject.toml" }],
    findings: [{
      origin_candidate: "pkg:pypi/urllib3@1.26.17",
      title: "CVE-2023-45803: Cookie leakage in urllib3",
      severity: "MEDIUM",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "1.26.18" }]
    }]
  };
  const pm = detectPackageManagers(scanC4);
  assert.strictEqual(pm.pythonPm, "poetry");
  const prompt = generateMasterAIFixPrompt(scanC4);
  assert(prompt.includes("poetry update urllib3"));
  assert(prompt.includes("poetry lock --no-update && poetry install"));
}

// C.5: uv with uv.lock
console.log("Running Test C.5: uv with uv.lock...");
{
  const scanC5 = {
    scan: { repository_url: "uv-repo", lockfile_types: ["uv.lock"] },
    files: [{ path: "uv.lock" }, { path: "pyproject.toml" }],
    findings: [{
      origin_candidate: "pkg:pypi/certifi@2023.7.22",
      title: "CVE-2023-37920: e-Tugra root cert removal in certifi",
      severity: "HIGH",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "2023.11.17" }]
    }]
  };
  const pm = detectPackageManagers(scanC5);
  assert.strictEqual(pm.pythonPm, "uv");
  const prompt = generateMasterAIFixPrompt(scanC5);
  assert(prompt.includes("uv lock --upgrade-package certifi"));
  assert(prompt.includes("uv lock && uv sync"));
}

// C.6: Pip with requirements.txt and no lockfile
console.log("Running Test C.6: Pip with requirements.txt and no lockfile...");
{
  const scanC6 = {
    scan: { repository_url: "pip-repo", lockfile_types: ["requirements.txt"] },
    files: [{ path: "requirements.txt" }],
    findings: [{
      origin_candidate: "pkg:pypi/cryptography@41.0.0",
      title: "CVE-2023-49083: NULL pointer dereference in cryptography",
      severity: "HIGH",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "41.0.6" }]
    }]
  };
  const pm = detectPackageManagers(scanC6);
  assert.strictEqual(pm.pythonPm, "pip");
  const prompt = generateMasterAIFixPrompt(scanC6);
  assert(prompt.includes("pip install -r requirements.txt"));
  assert(prompt.includes("Do NOT run `pip install -r requirements.txt --upgrade` as it forces upgrades on unrelated packages"));
  assert(prompt.includes("Plain pip does not generate a reproducible lockfile"));
}

// C.7: Conflicting package-manager evidence
console.log("Running Test C.7: Conflicting package-manager evidence...");
{
  const scanC7 = {
    scan: { repository_url: "conflict-repo" },
    files: [{ path: "package-lock.json" }, { path: "yarn.lock" }, { path: "package.json" }],
    findings: []
  };
  const pm = detectPackageManagers(scanC7);
  assert(pm.conflicts && pm.conflicts.length > 0, "Must detect lockfile conflicts");
  assert(pm.conflicts[0].includes("Multiple Node lockfiles detected"));

  const prompt = generateMasterAIFixPrompt(scanC7);
  assert(prompt.includes("CONFLICTING PACKAGE-MANAGER METADATA DETECTED"));
  assert(prompt.includes("Reconcile redundant lockfiles"));
}

// C.8: Failed lockfile resolution (safe failure protocol)
console.log("Running Test C.8: Failed lockfile resolution (safe failure protocol)...");
{
  const scanC8 = {
    scan: { repository_url: "fail-repo" },
    findings: []
  };
  const prompt = generateMasterAIFixPrompt(scanC8);
  assert(prompt.includes("Safe Failure Handling Protocol (Lockfile & Resolution Errors)"));
  assert(prompt.includes("**Preserve Original Evidence**: Do NOT delete existing lockfiles"));
  assert(prompt.includes("**No Guessing**: Avoid replacing lockfiles with guessed or hand-written content"));
  assert(prompt.includes("**Honest Reporting**: Declare lockfile synchronization status as FAILED or UNSYNCHRONIZED"));
}

// =========================================================================
// TEST GROUP D: DEPENDENCY CLASSIFICATION (6 TESTS)
// =========================================================================
console.log("\n--- TEST GROUP D: DEPENDENCY CLASSIFICATION ---");

// D.1: Direct dependency
console.log("Running Test D.1: Direct dependency...");
{
  const scanD1 = {
    scan: { repository_url: "direct-repo" },
    components: [
      { name: "fastapi", purl: "pkg:pypi/fastapi@0.95.0", is_direct: true, is_transitive: false, declared_in: "requirements.txt" }
    ],
    findings: [{
      origin_candidate: "pkg:pypi/fastapi@0.95.0",
      title: "CVE-2024-xxxx: ReDoS",
      severity: "LOW",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "0.100.0" }]
    }]
  };
  const pkgs = aggregateComponentPackages(scanD1);
  assert.strictEqual(pkgs[0].scope, "DIRECT");
  const prompt = generateMasterAIFixPrompt(scanD1);
  assert(prompt.includes("Scope**: DIRECT dependency (declared in `requirements.txt`)"));
}

// D.2: Transitive-only dependency
console.log("Running Test D.2: Transitive-only dependency...");
{
  const scanD2 = {
    scan: { repository_url: "transitive-repo" },
    components: [
      { name: "semver", purl: "pkg:npm/semver@5.7.1", is_direct: false, is_transitive: true, declared_in: "package-lock.json" }
    ],
    findings: [{
      origin_candidate: "pkg:npm/semver@5.7.1",
      title: "CVE-2022-25883: ReDoS in semver",
      severity: "HIGH",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "5.7.2" }]
    }]
  };
  const pkgs = aggregateComponentPackages(scanD2);
  assert.strictEqual(pkgs[0].scope, "TRANSITIVE");
  const prompt = generateMasterAIFixPrompt(scanD2);
  assert(prompt.includes("Scope**: TRANSITIVE dependency"));
  assert(prompt.includes("Do NOT add transitive dependencies into root `dependencies`"));
  assert(prompt.includes('"overrides"'));
}

// D.3: Same package both direct and transitive (MIXED)
console.log("Running Test D.3: Same package both direct and transitive (MIXED)...");
{
  const scanD3 = {
    scan: { repository_url: "mixed-repo" },
    components: [
      { name: "lodash", purl: "pkg:npm/lodash@4.17.15", is_direct: true, is_transitive: true }
    ],
    findings: [{
      origin_candidate: "pkg:npm/lodash@4.17.15",
      title: "CVE-2020-8203: Prototype Pollution",
      severity: "HIGH",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "4.17.19" }]
    }]
  };
  const pkgs = aggregateComponentPackages(scanD3);
  assert.strictEqual(pkgs[0].scope, "MIXED");
  const prompt = generateMasterAIFixPrompt(scanD3);
  assert(prompt.includes("Scope**: MIXED dependency"));
}

// D.4: Monorepo with multiple manifests
console.log("Running Test D.4: Monorepo with multiple manifests...");
{
  const scanD4 = {
    scan: { repository_url: "monorepo" },
    files: [
      { path: "frontend/package.json" },
      { path: "backend/package.json" },
      { path: "services/auth/package.json" }
    ],
    findings: []
  };
  const pm = detectPackageManagers(scanD4);
  assert.strictEqual(pm.workspaces.isWorkspace, true);
  assert.strictEqual(pm.workspaces.manifests.length, 3);
  const prompt = generateMasterAIFixPrompt(scanD4);
  assert(prompt.includes("Monorepo / Multi-Manifest Workspace Detected"));
  assert(prompt.includes("frontend/package.json"));
  assert(prompt.includes("backend/package.json"));
  assert(prompt.includes("services/auth/package.json"));
}

// D.5: Missing dependency-tree evidence (UNKNOWN)
console.log("Running Test D.5: Missing dependency-tree evidence (UNKNOWN)...");
{
  const scanD5 = {
    scan: { repository_url: "unknown-tree-repo" },
    components: [], // No component mapping
    findings: [{
      origin_candidate: "pkg:npm/orphan-pkg@1.0.0",
      title: "CVE-2024-xxxx",
      severity: "MEDIUM",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "1.0.1" }]
    }]
  };
  const pkgs = aggregateComponentPackages(scanD5);
  assert.strictEqual(pkgs[0].scope, "UNKNOWN");
  const prompt = generateMasterAIFixPrompt(scanD5);
  assert(prompt.includes("Scope**: UNKNOWN dependency"));
}

// D.6: Audit classification conflicting with actual repository evidence
console.log("Running Test D.6: Audit classification conflicting with actual repository evidence...");
{
  const scanD6 = {
    scan: { repository_url: "conflict-audit-repo" },
    components: [
      {
        name: "discrepant-pkg",
        purl: "pkg:npm/discrepant-pkg@2.0.0",
        is_direct: true,
        is_transitive: false,
        audit_discrepancy: "Audit marked as direct, but not declared in root package.json"
      }
    ],
    findings: [{
      origin_candidate: "pkg:npm/discrepant-pkg@2.0.0",
      title: "CVE-2024-xxxx",
      severity: "HIGH",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "2.0.5" }]
    }]
  };
  const pkgs = aggregateComponentPackages(scanD6);
  assert.strictEqual(pkgs[0].discrepancy, "Audit marked as direct, but not declared in root package.json");
  const prompt = generateMasterAIFixPrompt(scanD6);
  assert(prompt.includes("Audit Discrepancy**: Audit marked as direct, but not declared in root package.json"));
}

// =========================================================================
// TEST GROUP E: METADATA INTEGRITY (9 TESTS)
// =========================================================================
console.log("\n--- TEST GROUP E: METADATA INTEGRITY ---");

// E.1: Repository metadata matches the audit
console.log("Running Test E.1: Repository metadata matches the audit...");
{
  const scanE1 = {
    scan: { repository_url: "https://github.com/my-org/my-app" },
    findings: []
  };
  const prompt = generateMasterAIFixPrompt(scanE1, {
    expectedRepositoryUrl: "https://github.com/my-org/my-app"
  });
  assert(prompt.includes("Target Project / Repository**: `https://github.com/my-org/my-app`"));
  assert(!prompt.includes("REPOSITORY IDENTITY MISMATCH DETECTED"));
}

// E.2: Audit repository differs from selected repository
console.log("Running Test E.2: Audit repository differs from selected repository...");
{
  const scanE2 = {
    scan: { repository_url: "https://github.com/old-org/audit-source" },
    findings: []
  };
  const prompt = generateMasterAIFixPrompt(scanE2, {
    expectedRepositoryUrl: "https://github.com/new-org/target-project"
  });
  assert(prompt.includes("REPOSITORY IDENTITY MISMATCH DETECTED"));
  assert(prompt.includes("The audit data originates from `https://github.com/old-org/audit-source`"));
  assert(prompt.includes("active target repository is `https://github.com/new-org/target-project`"));
}

// E.3: Raw finding count differs from unique advisory count
console.log("Running Test E.3: Raw finding count differs from unique advisory count...");
{
  const scanE3 = {
    scan: { repository_url: "count-repo" },
    findings: [
      { id: "F1", origin_candidate: "pkg:npm/a@1.0.0", title: "CVE-2024-0001", severity: "HIGH", finding_type: "VULNERABLE", recommendations: [{ fixed_version: "1.0.1" }] },
      { id: "F2", origin_candidate: "pkg:npm/a@1.0.0", title: "CVE-2024-0001 (duplicate path)", severity: "HIGH", finding_type: "VULNERABLE", recommendations: [{ fixed_version: "1.0.1" }] },
      { id: "F3", origin_candidate: "pkg:npm/a@1.0.0", title: "CVE-2024-0001 (different sub-path)", severity: "HIGH", finding_type: "VULNERABLE", recommendations: [{ fixed_version: "1.0.1" }] },
      { id: "F4", origin_candidate: "pkg:npm/a@1.0.0", title: "CVE-2024-0002", severity: "LOW", finding_type: "VULNERABLE", recommendations: [{ fixed_version: "1.0.2" }] }
    ]
  };
  const prompt = generateMasterAIFixPrompt(scanE3);
  assert(prompt.includes("Total Raw Security Findings Reported**: 4"));
  assert(prompt.includes("Unique Security Advisories (CVE / GHSA / OSV)**: 2"));
  assert(prompt.includes("Unique Affected Packages / Components**: 1"));
}

// E.4: Duplicate advisories occur across different dependency paths
console.log("Running Test E.4: Duplicate advisories occur across different dependency paths...");
{
  const scanE4 = {
    scan: { repository_url: "paths-repo" },
    findings: [
      {
        id: "F1",
        origin_candidate: "pkg:npm/debug@2.6.9",
        dependency_path: "app -> morgan -> debug@2.6.9",
        title: "CVE-2017-16137: ReDoS in debug",
        severity: "HIGH",
        finding_type: "VULNERABLE",
        recommendations: [{ fixed_version: "2.6.9" }]
      },
      {
        id: "F2",
        origin_candidate: "pkg:npm/debug@2.6.9",
        dependency_path: "app -> body-parser -> debug@2.6.9",
        title: "CVE-2017-16137: ReDoS in debug",
        severity: "HIGH",
        finding_type: "VULNERABLE",
        recommendations: [{ fixed_version: "2.6.9" }]
      }
    ]
  };
  const pkgs = aggregateComponentPackages(scanE4);
  assert(pkgs[0].dependencyPaths && pkgs[0].dependencyPaths.length >= 2, "Must preserve distinct paths");
}

// E.5: Missing installed version
console.log("Running Test E.5: Missing installed version...");
{
  const scanE5 = {
    scan: { repository_url: "unversioned-repo" },
    findings: [{
      origin_candidate: "pkg:npm/unversioned-pkg",
      title: "CVE-2024-xxxx",
      severity: "LOW",
      finding_type: "VULNERABLE",
      recommendations: [{ fixed_version: "1.0.5" }]
    }]
  };
  const pkgs = aggregateComponentPackages(scanE5);
  assert.strictEqual(pkgs[0].installedVersion, "");
  assert.strictEqual(pkgs[0].resolution.category, "VERIFIED_MINIMUM_FIXED_VERSION");
  const prompt = generateMasterAIFixPrompt(scanE5);
  assert(prompt.includes("unversioned-pkg@installed"));
  assert(prompt.includes("VERIFIED_MINIMUM_FIXED_VERSION"));
}

// E.6: Invalid or unavailable target version
console.log("Running Test E.6: Invalid or unavailable target version...");
{
  const scanE6 = {
    scan: { repository_url: "invalid-target-repo" },
    findings: [{
      origin_candidate: "pkg:npm/ghost-pkg@1.0.0",
      title: "CVE-2024-xxxx: No fix exists",
      severity: "HIGH",
      finding_type: "VULNERABLE",
      recommendations: []
    }]
  };
  const prompt = generateMasterAIFixPrompt(scanE6);
  assert(prompt.includes("Manual Investigation Required"));
  assert(prompt.includes("NO_VERIFIED_FIX"));
}

// E.7: Unverified workflow SHA
console.log("Running Test E.7: Unverified workflow SHA...");
{
  // Test verifyActionSha directly
  const known = verifyActionSha("actions/checkout", "v4");
  assert.strictEqual(known.verified, true);
  assert.strictEqual(known.sha, "11bd71901bbe5b1630ceea73d27597364c9af683");

  const unknown = verifyActionSha("malicious-or-unknown/third-party-action", "v1");
  assert.strictEqual(unknown.verified, false);
  assert(unknown.warning?.includes("not in SupplyGraph's authoritative verified registry"));

  const finding = {
    title: "Unpinned action unknown-org/custom-action@v2",
    description: "Action uses mutable tag",
    finding_type: "CICD_RISK"
  };
  const snippet = buildLockfileSnippet(finding);
  assert(snippet.includes("Do NOT invent an unverified SHA"));
  assert(snippet.includes("Manual investigation required"));
}

// E.8: Empty or incomplete audit
console.log("Running Test E.8: Empty or incomplete audit...");
{
  const emptyScan = {
    scan: { repository_url: "https://github.com/clean-project/app", total_findings: 0 },
    findings: [],
    code_reviews: []
  };
  const prompt = generateMasterAIFixPrompt(emptyScan);
  assert(prompt.includes("Total Raw Security Findings Reported**: 0"));
  assert(prompt.includes("Unique Security Advisories (CVE / GHSA / OSV)**: 0"));
  assert(prompt.includes("0 actionable risks detected across audited workflow files"));
  assert(prompt.includes("Scope of performed CI/CD checks"));
}

// E.9: Synthetic fixtures do not leak into production output
console.log("Running Test E.9: Synthetic fixtures do not leak into production output...");
{
  const genericScan = {
    scan: {},
    findings: []
  };
  const prompt = generateMasterAIFixPrompt(genericScan);
  assert(!prompt.includes("kisan-ai-core"));
  assert(!prompt.includes("spacebasic"));
  assert(prompt.includes("Target Project / Repository**: `Target Repository / Local Project`"));
}

// =========================================================================
// TEST GROUP E2E: END-TO-END PROMPT GENERATION PIPELINE (1 TEST)
// =========================================================================
console.log("\n--- TEST GROUP E2E: REAL PIPELINE END-TO-END TEST ---");
console.log("Running Test E2E: Comprehensive multi-ecosystem repository audit...");
{
  const e2eScan = {
    scan: {
      repository_url: "https://github.com/enterprise/fullstack-app",
      total_findings: 4,
      blast_radius_score: 65,
      lockfile_types: ["package-lock.json", "poetry.lock"]
    },
    files: [
      { path: "package.json" },
      { path: "package-lock.json" },
      { path: "pyproject.toml" },
      { path: "poetry.lock" },
      { path: ".github/workflows/ci.yml" }
    ],
    components: [
      { name: "axios", purl: "pkg:npm/axios@0.21.1", is_direct: true, is_transitive: false, declared_in: "package.json" },
      { name: "cryptography", purl: "pkg:pypi/cryptography@38.0.0", is_direct: true, is_transitive: false, declared_in: "pyproject.toml" },
      { name: "tough-cookie", purl: "pkg:npm/tough-cookie@2.5.0", is_direct: false, is_transitive: true, declared_in: "package-lock.json" }
    ],
    findings: [
      {
        id: "FINDING-AXIOS",
        origin_candidate: "pkg:npm/axios@0.21.1",
        title: "CVE-2023-45857: SSRF in axios",
        severity: "HIGH",
        finding_type: "VULNERABLE",
        recommendations: [{ fixed_version: "0.21.4" }]
      },
      {
        id: "FINDING-CRYPTO",
        origin_candidate: "pkg:pypi/cryptography@38.0.0",
        title: "CVE-2023-23931: Memory corruption in cryptography",
        severity: "HIGH",
        finding_type: "VULNERABLE",
        recommendations: [{ fixed_version: "39.0.1" }]
      },
      {
        id: "FINDING-COOKIE",
        origin_candidate: "pkg:npm/tough-cookie@2.5.0",
        title: "CVE-2023-26136: Prototype pollution in tough-cookie",
        severity: "MEDIUM",
        finding_type: "VULNERABLE",
        recommendations: [{ fixed_version: "4.1.3" }]
      }
    ],
    code_reviews: [
      {
        title: "Mutable GitHub Action Tag",
        severity: "MEDIUM",
        file_path: ".github/workflows/ci.yml",
        line_number: 18,
        error_explanation: "Pin actions/setup-node to immutable SHA",
        unified_diff: "- uses: actions/setup-node@v4\n+ uses: actions/setup-node@1d0ff469b7ec7b3cb9d8673fde0c81c44821de2a # v4.2.0"
      }
    ]
  };

  const masterPrompt = generateMasterAIFixPrompt(e2eScan, {
    expectedRepositoryUrl: "https://github.com/enterprise/fullstack-app"
  });

  // Verify Defect 1: All claims grounded, versions verified, no false claims
  assert(masterPrompt.includes("VERIFIED_FIXED_VERSION"));
  assert(masterPrompt.includes('"axios": "^0.21.4"'));
  assert(masterPrompt.includes("COMPATIBILITY_REVIEW_REQUIRED")); // tough-cookie 2.5 -> 4.1.3 is major upgrade!
  assert(masterPrompt.includes('Do NOT promise "zero regressions"'));
  assert(!masterPrompt.includes("Your mission is to fix ALL issues below with zero regressions"));

  // Verify Defect 2: 3-Tier Modification Scope Policy
  assert(masterPrompt.includes("Structured 3-Tier Modification Scope Policy"));
  assert(masterPrompt.includes("Category A — Expected Remediation Files"));
  assert(masterPrompt.includes("Category B — Necessary Compatibility Files (Call-Sites)"));
  assert(masterPrompt.includes("Category C — Unrelated Project Files (STRICTLY PROHIBITED)"));
  assert(masterPrompt.includes("Call-Site Dependency Audit & API Compatibility Refactoring (Category B)"));

  // Verify Defect 3: Targeted tool commands & lockfile synchronization
  assert(masterPrompt.includes("npm install axios@0.21.4 --package-lock-only"));
  assert(masterPrompt.includes("poetry update cryptography"));
  assert(masterPrompt.includes("Safe Failure Handling Protocol (Lockfile & Resolution Errors)"));

  // Verify Defect 4: Evidence-based Direct vs Transitive scopes
  assert(masterPrompt.includes("Scope**: DIRECT dependency (declared in `package.json`)"));
  assert(masterPrompt.includes("Scope**: TRANSITIVE dependency"));
  assert(masterPrompt.includes('"overrides"'));

  // Verify Defect 5: Validated metadata & SHA verification
  assert(masterPrompt.includes("Target Project / Repository**: `https://github.com/enterprise/fullstack-app`"));
  assert(masterPrompt.includes("Total Raw Security Findings Reported**: 3"));
  assert(masterPrompt.includes("CI/CD Pipeline Security Findings**: 1"));
  assert(masterPrompt.includes("1d0ff469b7ec7b3cb9d8673fde0c81c44821de2a")); // Verified SHA
  assert(!masterPrompt.includes("REPOSITORY IDENTITY MISMATCH DETECTED"));

  console.log("End-to-End master remediation prompt successfully generated and validated across all 5 defect categories!");
}

console.log("\n=========================================================================");
console.log("🏆 ALL 51 ACCEPTANCE & DEFECT HARDENING REGRESSION TESTS PASSED (100%)!");
console.log("=========================================================================\n");

