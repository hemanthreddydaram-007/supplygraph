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

console.log("\n🎯 ALL 15 ACCEPTANCE AND REGRESSION TEST SUITES PASSED FLAWLESSLY!\n");
