/**
 * SupplyGraph - Enterprise Evidence-Based AI Security Remediation Prompt Generator
 * 
 * Generates accurate, repository-aware, evidence-grounded remediation prompts for AI coding agents:
 * - Antigravity
 * - Cursor
 * - Claude Code
 * - GitHub Copilot
 * - ChatGPT
 * 
 * Conforms strictly to OpenSSF, PEP 440, and SemVer specifications.
 * Enforces a 5-Phase Security Remediation Workflow (Baseline -> Plan -> Implement -> Verify -> Report)
 * with an explicit 3-Tier Modification Scope Policy and multi-advisory candidate resolution.
 */

export type VersionConfidenceCategory =
  | "VERIFIED_FIXED_VERSION"
  | "VERIFIED_MINIMUM_FIXED_VERSION"
  | "COMPATIBILITY_REVIEW_REQUIRED"
  | "NO_VERIFIED_FIX"
  | "MANUAL_INVESTIGATION_REQUIRED"
  // Backward-compatibility aliases
  | "VERIFIED_SAME_MAJOR"
  | "VERIFIED_MAJOR_UPGRADE"
  | "MINIMUM_KNOWN_FIXED"
  | "INVESTIGATION_REQUIRED";

export type DependencyScope = "DIRECT" | "TRANSITIVE" | "MIXED" | "UNKNOWN" | "DIRECT_AND_TRANSITIVE";

export type SupportedEcosystem = "npm" | "pypi" | "golang" | "cargo" | "ci/cd" | "ast" | "unknown";

export type DetectedPackageManager = "npm" | "pnpm" | "yarn" | "bun" | "pip" | "poetry" | "pipenv" | "uv" | "go" | "cargo" | "unknown";

export interface SemVerParsed {
  major: number;
  minor: number;
  patch: number;
  raw: string;
}

export interface VersionResolution {
  rawFixed: string;
  cleanVersion: string;
  category: VersionConfidenceCategory;
  isMajorUpgrade: boolean;
  majorDiff: number;
  explanation: string;
  pep440Constraint?: string;
  npmConstraint?: string;
  candidateSatisfiesAllAdvisories?: boolean;
}

export interface AdvisoryDetail {
  id: string;
  title: string;
  severity: string;
  description?: string;
  fixedVersion?: string;
  affectedRange?: string;
  sourceUrl?: string;
}

export interface ComponentRemediationPackage {
  key: string;
  pkgName: string;
  installedVersion: string;
  ecosystem: SupportedEcosystem;
  scope: DependencyScope;
  declaredIn?: string;
  discrepancy?: string;
  findings: any[];
  highestSeverity: string;
  advisories: AdvisoryDetail[];
  resolution: VersionResolution;
  isDev?: boolean;
  dependencyPaths?: string[];
}

export interface PromptGeneratorOptions {
  batchSize?: number;
  targetBranch?: string;
  includeAstRefactoring?: boolean;
  includeCicdHardening?: boolean;
  expectedRepositoryUrl?: string;
}

export interface DetectedWorkspaceInfo {
  manifests: string[];
  isWorkspace: boolean;
  packageManager: "npm" | "pnpm" | "yarn" | "bun";
}

export interface PackageManagerDetectionResult {
  nodePm: "npm" | "pnpm" | "yarn" | "bun";
  pythonPm: "pip" | "poetry" | "pipenv" | "uv";
  hasGo: boolean;
  hasCargo: boolean;
  workspaces: DetectedWorkspaceInfo;
  manifestPaths: string[];
  conflicts?: string[];
}

// Authoritative SHA registry for official and verified GitHub Actions
export const VERIFIED_ACTION_SHAS: Record<string, Record<string, string>> = {
  "actions/checkout": {
    "v4": "11bd71901bbe5b1630ceea73d27597364c9af683",  // v4.2.2
    "v3": "f43a0e5ff2bd294095638e18286ca9a3d1956744",  // v3.6.0
    "v2": "ee0669bd1cc54295c223e0bb666b733df41de133",  // v2.7.0
    "default": "11bd71901bbe5b1630ceea73d27597364c9af683",
    "comment": "v4.2.2",
  },
  "actions/setup-python": {
    "v5": "42375524e23c412d93fb67b49958b491fce71c38",  // v5.4.0
    "v4": "65d7f2d534ac1bc67fcd62888c5f4f3d2cb2b236",  // v4.7.1
    "v3": "d27e3f3d7c64b4bbf8e4abfb9b63b83e846e0435",  // v3.1.4
    "default": "42375524e23c412d93fb67b49958b491fce71c38",
    "comment": "v5.4.0",
  },
  "actions/setup-node": {
    "v4": "1d0ff469b7ec7b3cb9d8673fde0c81c44821de2a",  // v4.2.0
    "v3": "60edb5dd545a775178f52524783378180af0d1f8",  // v3.8.1
    "default": "1d0ff469b7ec7b3cb9d8673fde0c81c44821de2a",
    "comment": "v4.2.0",
  },
  "actions/setup-go": {
    "v5": "f111f3307d8850f501ac008e886eec1fd1932a34",  // v5.3.0
    "v4": "93397bea11091df50f3d7e59dc26a7711a8bcfbe",  // v4.1.0
    "default": "f111f3307d8850f501ac008e886eec1fd1932a34",
    "comment": "v5.3.0",
  },
  "actions/setup-java": {
    "v4": "8df10395653b0da29d1b493f1117450e60e7e662",  // v4.6.1
    "v3": "cd89f464f9363072223a47ca23783909771e8bfb",  // v3.13.0
    "default": "8df10395653b0da29d1b493f1117450e60e7e662",
    "comment": "v4.6.1",
  },
  "actions/upload-artifact": {
    "v4": "b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882",  // v4.4.3
    "v3": "0b7f8abb1508181956e8e162db84b466c27e18ce",  // v3.1.3
    "default": "b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882",
    "comment": "v4.4.3",
  },
  "actions/download-artifact": {
    "v4": "fa0a91b85d4f404e444e00e005971372dc801d16",  // v4.1.8
    "v3": "9bc31d5ccc31df68ecc42ccf4149144866c47d8a",  // v3.0.2
    "default": "fa0a91b85d4f404e444e00e005971372dc801d16",
    "comment": "v4.1.8",
  },
  "actions/cache": {
    "v4": "1bd1e32a3bdc45362d1e726936510720a7c30a57",  // v4.2.0
    "v3": "704facf57e6136b1bc63b828d79edcd491f0ee84",  // v3.3.2
    "default": "1bd1e32a3bdc45362d1e726936510720a7c30a57",
    "comment": "v4.2.0",
  },
  "docker/login-action": {
    "v3": "9780b0c442fbb1117ed29e0efdff1e18412f7567",  // v3.3.0
    "default": "9780b0c442fbb1117ed29e0efdff1e18412f7567",
    "comment": "v3.3.0",
  },
  "docker/build-push-action": {
    "v6": "471d1dc4e07e5cdedd9c21719d54b79e1b20a4ec",  // v6.15.0
    "v5": "4a13e500e55cf31b7a5d59a38ab2040ab0f42f56",  // v5.1.0
    "default": "471d1dc4e07e5cdedd9c21719d54b79e1b20a4ec",
    "comment": "v6.15.0",
  },
  "docker/setup-buildx-action": {
    "v3": "b5ca514318bd6ebac0fb2aedd5d36ec1b5c232a2",  // v3.10.0
    "default": "b5ca514318bd6ebac0fb2aedd5d36ec1b5c232a2",
    "comment": "v3.10.0",
  },
  "codecov/codecov-action": {
    "v5": "015ff539bb73772273d524247214d05e1242179e",  // v5.0.7
    "v4": "e28ff129e5465c2c0dcc6f003fc735cb6ae0c673",  // v4.5.0
    "default": "015ff539bb73772273d524247214d05e1242179e",
    "comment": "v5.0.7",
  },
};

/**
 * Authoritatively verifies whether a GitHub Action and tag has a confirmed SHA pin in registry.
 */
export function verifyActionSha(
  actionName: string,
  refTag: string = "default"
): { verified: boolean; sha?: string; comment?: string; warning?: string } {
  const cleanAction = actionName.trim().toLowerCase();
  const matchedKey = Object.keys(VERIFIED_ACTION_SHAS).find(k => k.toLowerCase() === cleanAction);
  if (!matchedKey) {
    return {
      verified: false,
      warning: `Action '${actionName}' is not in SupplyGraph's authoritative verified registry. Query official repository before SHA pinning.`,
    };
  }

  const actionMap = VERIFIED_ACTION_SHAS[matchedKey];
  const cleanTag = refTag.replace(/^@/, "").trim().toLowerCase();
  
  const tagKey = Object.keys(actionMap).find(k => k.toLowerCase() === cleanTag);
  const sha = tagKey ? actionMap[tagKey] : actionMap["default"];
  const comment = actionMap["comment"] || cleanTag;

  if (!sha) {
    return {
      verified: false,
      warning: `Tag '${refTag}' for action '${actionName}' has no verified SHA mapping. Manual investigation required.`,
    };
  }

  return {
    verified: true,
    sha,
    comment,
  };
}

/**
 * Robust SemVer parser. Strips prefixes (v, ^, ~, >=, ==) and parses numeric components.
 */
export function parseSemVer(v: string | null | undefined): SemVerParsed | null {
  if (!v || typeof v !== "string") return null;
  const clean = v.trim().replace(/^[v^~>=<\s]+/, "");
  if (!clean || clean.toLowerCase() === "latest" || clean.includes("patched_version")) {
    return null;
  }
  const m = clean.match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?(.*)$/);
  if (!m) return null;
  return {
    major: parseInt(m[1], 10),
    minor: m[2] !== undefined ? parseInt(m[2], 10) : 0,
    patch: m[3] !== undefined ? parseInt(m[3], 10) : 0,
    raw: clean,
  };
}

/**
 * Compares two SemVer strings. Returns positive if v1 > v2, negative if v1 < v2, 0 if equal.
 */
export function compareSemVer(v1: any, v2: any): number {
  const str1 = typeof v1 === "string" ? v1 : String(v1 || "");
  const str2 = typeof v2 === "string" ? v2 : String(v2 || "");
  const pa = parseSemVer(str1);
  const pb = parseSemVer(str2);
  if (!pa && !pb) return 0;
  if (!pa) return -1;
  if (!pb) return 1;
  if (pa.major !== pb.major) return pa.major - pb.major;
  if (pa.minor !== pb.minor) return pa.minor - pb.minor;
  if (pa.patch !== pb.patch) return pa.patch - pb.patch;
  return 0;
}

export interface ResolveVersionOptions {
  conflictingSources?: boolean;
  sourceUnavailable?: boolean;
  advisories?: AdvisoryDetail[];
}

/**
 * Resolves the optimal safe version from candidate fixes, returning explicit states:
 * - VERIFIED_FIXED_VERSION: Confirmed patch release in same major version satisfying all verified advisories.
 * - VERIFIED_MINIMUM_FIXED_VERSION: Minimum confirmed fix (when installed version is unversioned or lowest safe floor).
 * - COMPATIBILITY_REVIEW_REQUIRED: Major-version upgrade crossing major boundary (migration assessment).
 * - NO_VERIFIED_FIX: Unpatched, disputed, or zero-day advisory.
 * - MANUAL_INVESTIGATION_REQUIRED: Non-standard version, conflicting upstream sources, or unavailable external source.
 */
export function resolveVersionWithConfidence(
  installedVer: string | null | undefined,
  candidateFixes: (string | null | undefined)[],
  options?: ResolveVersionOptions
): VersionResolution {
  if (options?.sourceUnavailable) {
    return {
      rawFixed: "",
      cleanVersion: "",
      category: "MANUAL_INVESTIGATION_REQUIRED",
      isMajorUpgrade: false,
      majorDiff: 0,
      explanation: "Authoritative external advisory source was unavailable during audit. Manual advisory verification required.",
    };
  }

  if (options?.conflictingSources) {
    return {
      rawFixed: "",
      cleanVersion: "",
      category: "MANUAL_INVESTIGATION_REQUIRED",
      isMajorUpgrade: false,
      majorDiff: 0,
      explanation: "Conflicting upstream advisory evidence detected across data sources. Manual verification required before upgrading.",
    };
  }

  const cleanCandidates = Array.from(new Set(
    candidateFixes
      .map((c) => (typeof c === "string" ? c.trim() : String(c || "").trim()))
      .filter((c) => Boolean(c) && c.toLowerCase() !== "latest" && !c.includes("patched_version"))
  ));

  const advisories = options?.advisories || [];
  const hasUnpatchedAdvisory = advisories.some(a => !a.fixedVersion || a.fixedVersion.trim() === "" || a.fixedVersion.toLowerCase() === "latest");

  if (cleanCandidates.length === 0) {
    return {
      rawFixed: "",
      cleanVersion: "",
      category: "NO_VERIFIED_FIX",
      isMajorUpgrade: false,
      majorDiff: 0,
      explanation: "No upstream patched release found in security databases (disputed or unpatched advisory). Manual vendor investigation required.",
    };
  }

  const instParsed = parseSemVer(installedVer);

  // If installed version cannot be parsed, pick lowest valid candidate as minimum known
  if (!instParsed) {
    const valid = cleanCandidates.map(c => ({ raw: c, p: parseSemVer(c) })).filter(item => item.p !== null);
    if (valid.length > 0) {
      valid.sort((a, b) => compareSemVer(a.raw, b.raw));
      return {
        rawFixed: valid[0].raw,
        cleanVersion: valid[0].raw,
        category: "VERIFIED_MINIMUM_FIXED_VERSION",
        isMajorUpgrade: false,
        majorDiff: 0,
        explanation: `Minimum known fixed release is ${valid[0].raw}. Current installed version is unversioned or non-standard.`,
        pep440Constraint: `>=${valid[0].raw}`,
        npmConstraint: `^${valid[0].raw}`,
      };
    }
    return {
      rawFixed: cleanCandidates[0],
      cleanVersion: cleanCandidates[0],
      category: "MANUAL_INVESTIGATION_REQUIRED",
      isMajorUpgrade: false,
      majorDiff: 0,
      explanation: "Non-standard version format. Verify package release notes before upgrading.",
    };
  }

  const parsedCandidates = cleanCandidates
    .map((raw) => ({ raw, parsed: parseSemVer(raw) }))
    .filter((item): item is { raw: string; parsed: NonNullable<ReturnType<typeof parseSemVer>> } => item.parsed !== null);

  if (parsedCandidates.length === 0) {
    return {
      rawFixed: cleanCandidates[0],
      cleanVersion: cleanCandidates[0],
      category: "MANUAL_INVESTIGATION_REQUIRED",
      isMajorUpgrade: false,
      majorDiff: 0,
      explanation: "Advisory lists non-SemVer release tags. Manual verification needed.",
    };
  }

  // Check candidate fixes relative to installed version
  const validUpgrades = parsedCandidates.filter(c => compareSemVer(c.raw, installedVer) >= 0);
  if (validUpgrades.length === 0) {
    return {
      rawFixed: "",
      cleanVersion: "",
      category: "NO_VERIFIED_FIX",
      isMajorUpgrade: false,
      majorDiff: 0,
      explanation: "Available advisory fixes apply only to older release branches. Upstream has not published a fix for this branch.",
    };
  }

  // If unpatched advisory exists alongside candidate fixes:
  if (hasUnpatchedAdvisory) {
    return {
      rawFixed: "",
      cleanVersion: "",
      category: "NO_VERIFIED_FIX",
      isMajorUpgrade: false,
      majorDiff: 0,
      explanation: "Package contains unpatched advisory with no published upstream fix. Partial candidate fixes exist for other advisories, but package cannot be claimed fully fixed. Manual investigation required.",
    };
  }

  // Multi-advisory candidate resolution:
  // Candidate version must satisfy ALL verified advisories for this package.
  // Each advisory with a known fix requires version >= advisory.fixedVersion.
  // Therefore, candidate version must be >= max(advisories.fixedVersion).
  let requiredFloor = validUpgrades[0].raw;
  for (const c of validUpgrades) {
    if (compareSemVer(c.raw, requiredFloor) > 0) {
      requiredFloor = c.raw;
    }
  }

  if (advisories.length > 0) {
    const fixedAdvisories = advisories.filter(a => Boolean(a.fixedVersion && parseSemVer(a.fixedVersion)));
    if (fixedAdvisories.length > 0) {
      let maxAdvFix = fixedAdvisories[0].fixedVersion!;
      for (const a of fixedAdvisories) {
        if (compareSemVer(a.fixedVersion!, maxAdvFix) > 0) {
          maxAdvFix = a.fixedVersion!;
        }
      }
      if (compareSemVer(maxAdvFix, requiredFloor) > 0) {
        requiredFloor = maxAdvFix;
      }
    }
  }

  const floorParsed = parseSemVer(requiredFloor);
  if (!floorParsed) {
    return {
      rawFixed: requiredFloor,
      cleanVersion: requiredFloor,
      category: "MANUAL_INVESTIGATION_REQUIRED",
      isMajorUpgrade: false,
      majorDiff: 0,
      explanation: "Candidate version format could not be verified.",
    };
  }

  // 1. Same major version upgrade
  if (floorParsed.major === instParsed.major) {
    const sameMajorSatisfying = validUpgrades.filter(c =>
      c.parsed.major === instParsed.major && compareSemVer(c.raw, requiredFloor) >= 0
    );
    sameMajorSatisfying.sort((a, b) => compareSemVer(b.raw, a.raw));
    const best = sameMajorSatisfying.length > 0 ? sameMajorSatisfying[0].raw : requiredFloor;

    return {
      rawFixed: best,
      cleanVersion: best,
      category: "VERIFIED_FIXED_VERSION",
      isMajorUpgrade: false,
      majorDiff: 0,
      explanation: `Verified patch release within major version ${instParsed.major} (resolves all known advisories with minimized breaking change risk).`,
      pep440Constraint: `>=${best}`,
      npmConstraint: `^${best}`,
      candidateSatisfiesAllAdvisories: true,
    };
  }

  // 2. Major version upgrade required to satisfy all advisories
  if (floorParsed.major > instParsed.major) {
    const diff = floorParsed.major - instParsed.major;
    return {
      rawFixed: requiredFloor,
      cleanVersion: requiredFloor,
      category: "COMPATIBILITY_REVIEW_REQUIRED",
      isMajorUpgrade: true,
      majorDiff: diff,
      explanation: `⚠️ Major version upgrade required (${instParsed.major}.x -> ${floorParsed.major}.x) to satisfy all advisories. Potential breaking API changes require migration assessment.`,
      pep440Constraint: `>=${requiredFloor}`,
      npmConstraint: `^${requiredFloor}`,
      candidateSatisfiesAllAdvisories: true,
    };
  }

  return {
    rawFixed: "",
    cleanVersion: "",
    category: "NO_VERIFIED_FIX",
    isMajorUpgrade: false,
    majorDiff: 0,
    explanation: "Candidate versions do not satisfy current branch constraints.",
  };
}

/**
 * Backward-compatible helper returning the safe version string or null.
 */
export function resolveHighestSafeVersion(
  installedVer: string | null | undefined,
  candidateFixes: (string | null | undefined)[]
): string | null {
  const res = resolveVersionWithConfidence(installedVer, candidateFixes);
  return res.cleanVersion || null;
}

/**
 * Identifies component name, installed version, and ecosystem from finding metadata.
 */
export function getFindingPackage(f: any): { pkgName: string; version: string; ecosystem: SupportedEcosystem; key: string } {
  const origin = f?.origin_candidate || f?.title || "";
  let clean = origin.replace(/^Vulnerability in\s*/i, "").replace(/^pkg:(npm|pypi|cargo|golang)\//i, "");
  try { clean = decodeURIComponent(clean); } catch (_) {}

  let eco: SupportedEcosystem = "pypi";
  if (origin.includes("pkg:npm/") || origin.includes("npm") || clean.startsWith("@")) {
    eco = "npm";
  } else if (origin.includes("pkg:golang/") || origin.includes("golang") || clean.startsWith("golang.org/") || clean.startsWith("github.com/")) {
    eco = "golang";
  } else if (origin.includes("pkg:cargo/") || origin.includes("cargo")) {
    eco = "cargo";
  } else if (origin.includes("pkg:pypi/") || origin.includes("pypi")) {
    eco = "pypi";
  } else if (f?.finding_type === "CICD_RISK" || origin.includes(".github/workflows")) {
    eco = "ci/cd";
  } else if (f?.finding_type === "AST") {
    eco = "ast";
  }

  let pkgName = clean;
  let version = "";

  if (clean.startsWith("@")) {
    const atIdx = clean.indexOf("@", 1);
    if (atIdx !== -1) {
      pkgName = clean.substring(0, atIdx);
      version = clean.substring(atIdx + 1);
    }
  } else {
    const atIdx = clean.indexOf("@");
    if (atIdx !== -1) {
      pkgName = clean.substring(0, atIdx);
      version = clean.substring(atIdx + 1);
    }
  }

  if (f?.finding_type === "CICD_RISK") {
    pkgName = "GitHub Actions Workflows";
    eco = "ci/cd";
  } else if (!pkgName || pkgName.trim() === "") {
    pkgName = f?.entity_type || "Direct Project Dependency";
  }

  return {
    pkgName,
    version,
    ecosystem: eco,
    key: `${pkgName}${version ? `@${version}` : ""}`,
  };
}

/**
 * Inspects scan data to detect package managers, lockfiles, workspace layouts, and packaging conflicts.
 */
export function detectPackageManagers(scanData: any): PackageManagerDetectionResult {
  const lockTypes: string[] = scanData?.scan?.lockfile_types || [];
  const files: { path: string }[] = scanData?.files || [];
  const filePaths = new Set([...lockTypes, ...files.map(f => f.path)]);
  const conflicts: string[] = [];

  const hasNpmLock = Array.from(filePaths).some(p => p.includes("package-lock.json"));
  const hasPnpmLock = Array.from(filePaths).some(p => p.includes("pnpm-lock.yaml"));
  const hasYarnLock = Array.from(filePaths).some(p => p.includes("yarn.lock"));
  const hasBunLock = Array.from(filePaths).some(p => p.includes("bun.lockb") || p.includes("bun.lock"));

  const detectedNodeLocks = [
    hasNpmLock ? "package-lock.json" : null,
    hasPnpmLock ? "pnpm-lock.yaml" : null,
    hasYarnLock ? "yarn.lock" : null,
    hasBunLock ? "bun.lockb" : null,
  ].filter(Boolean) as string[];

  if (detectedNodeLocks.length > 1) {
    conflicts.push(`Multiple Node lockfiles detected (${detectedNodeLocks.join(", ")}). Reconcile redundant lockfiles to prevent dependency drift.`);
  }

  let nodePm: "npm" | "pnpm" | "yarn" | "bun" = "npm";
  if (hasPnpmLock) nodePm = "pnpm";
  else if (hasYarnLock) nodePm = "yarn";
  else if (hasBunLock) nodePm = "bun";

  const hasPoetryLock = Array.from(filePaths).some(p => p.includes("poetry.lock"));
  const hasPipfileLock = Array.from(filePaths).some(p => p.includes("Pipfile.lock") || p.includes("Pipfile"));
  const hasUvLock = Array.from(filePaths).some(p => p.includes("uv.lock"));
  const hasReqTxt = Array.from(filePaths).some(p => p.includes("requirements.txt"));

  const detectedPyTools = [
    hasPoetryLock ? "poetry.lock" : null,
    hasPipfileLock ? "Pipfile.lock" : null,
    hasUvLock ? "uv.lock" : null,
    hasReqTxt ? "requirements.txt" : null,
  ].filter(Boolean) as string[];

  if ([hasPoetryLock, hasPipfileLock, hasUvLock].filter(Boolean).length > 1) {
    conflicts.push(`Multiple Python package manager lockfiles detected (${detectedPyTools.join(", ")}). Designate a single authoritative tool.`);
  }

  let pythonPm: "pip" | "poetry" | "pipenv" | "uv" = "pip";
  if (hasPoetryLock) pythonPm = "poetry";
  else if (hasPipfileLock) pythonPm = "pipenv";
  else if (hasUvLock) pythonPm = "uv";

  const hasGo = Array.from(filePaths).some(p => p.includes("go.mod") || p.includes("go.sum"));
  const hasCargo = Array.from(filePaths).some(p => p.includes("Cargo.toml") || p.includes("Cargo.lock"));

  const manifestPaths = Array.from(filePaths).filter(p =>
    p.endsWith("package.json") ||
    p.endsWith("requirements.txt") ||
    p.endsWith("pyproject.toml") ||
    p.endsWith("go.mod") ||
    p.endsWith("Cargo.toml")
  );

  const nodeManifests = manifestPaths.filter(p => p.endsWith("package.json"));
  const isWorkspace = nodeManifests.length > 1;

  return {
    nodePm,
    pythonPm,
    hasGo,
    hasCargo,
    manifestPaths,
    conflicts: conflicts.length > 0 ? conflicts : undefined,
    workspaces: {
      manifests: nodeManifests,
      isWorkspace,
      packageManager: nodePm,
    },
  };
}

/**
 * Builds lockfile configuration snippets with authoritative verification.
 */
export function buildLockfileSnippet(finding: any, forcedFixVer?: string): string {
  const findingType: string = finding?.finding_type || "";
  const { pkgName, ecosystem } = getFindingPackage(finding);
  const isPypi = ecosystem === "pypi";

  // 1. Dependency Confusion
  if (findingType === "DEPENDENCY_CONFUSION") {
    for (const ev of finding?.evidence || []) {
      if (ev?.raw_data?.remediation) return ev.raw_data.remediation;
    }
    const scope = pkgName.startsWith("@") ? pkgName.split("/")[0] : `@${pkgName.split("-")[0]}`;
    if (!isPypi) {
      return `// .npmrc registry scope configuration\n${scope}:registry=https://npm.pkg.github.com\n//npm.pkg.github.com/:_authToken=\${NODE_AUTH_TOKEN}`;
    } else {
      return `# pip.conf registry scope configuration\n[global]\nextra-index-url = https://pypi.org/simple\nindex-url = https://private-pypi.company.internal/simple`;
    }
  }

  // 2. Typosquatting
  if (findingType === "TYPOSQUATTING") {
    let similarTo = "";
    for (const ev of finding?.evidence || []) {
      if (ev?.raw_data?.similar_to) {
        similarTo = ev.raw_data.similar_to;
        break;
      }
    }
    if (ecosystem === "npm") {
      return `// Remediation: Remove rogue typosquat\nnpm uninstall ${pkgName}${similarTo ? `\nnpm install ${similarTo}` : ""}`;
    } else {
      return `# Remediation: Remove rogue typosquat\npip uninstall -y ${pkgName}${similarTo ? `\npip install ${similarTo}` : ""}`;
    }
  }

  // 3. CI/CD Risk
  if (findingType === "CICD_RISK") {
    const titleOrDesc = `${finding?.title || ""} ${finding?.description || ""}`;
    const actionMatch = titleOrDesc.match(/([a-zA-Z0-9-]+\/[a-zA-Z0-9_-]+)(?:@([v0-9a-zA-Z._-]+))?/);
    if (actionMatch) {
      const actionMentioned = actionMatch[1];
      const tag = actionMatch[2] || "default";
      const verResult = verifyActionSha(actionMentioned, tag);
      if (verResult.verified && verResult.sha) {
        return `# .github/workflows/*.yml - Enforce least-privilege permissions\npermissions:\n  contents: read\n  pull-requests: write\n# Immutable commit SHA pin verified by SupplyGraph:\nuses: ${actionMentioned}@${verResult.sha} # ${verResult.comment}`;
      } else {
        return `# .github/workflows/*.yml - Enforce least-privilege permissions\npermissions:\n  contents: read\n  pull-requests: write\n# ⚠️ Action '${actionMentioned}' is not in verified registry. Do NOT invent an unverified SHA.\n# Manual investigation required: verify commit SHA via official action repository before pinning:\n# uses: ${actionMentioned}@<VERIFIED_40_CHAR_SHA> # ${tag}`;
      }
    }
    return `# .github/workflows/*.yml - Enforce least-privilege permissions\npermissions:\n  contents: read\n  pull-requests: write\n# Pin verified actions to full 40-character commit SHA with version comment:\n# uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2`;
  }

  // 4. AST / Suspicious Code Patterns
  if (findingType === "SUSPICIOUS" || findingType === "OBFUSCATION" || findingType === "DORMANT_LOGIC") {
    return `# Source Code Remediation (AST)\n# 1. Replace eval() / exec() with json.loads() or ast.literal_eval\n# 2. Avoid subprocess(..., shell=True) - pass arguments as a list: subprocess.run(['cmd', 'arg'])\n# 3. Store API credentials in environment variables (os.environ.get('KEY'))`;
  }

  // 5. Known Vulnerabilities
  let fixedVer: string = forcedFixVer || finding?.recommendations?.[0]?.fixed_version || "";
  if (!fixedVer && finding?.recommendations) {
    for (const rec of finding.recommendations) {
      if (rec?.fixed_version) {
        fixedVer = rec.fixed_version;
        break;
      }
    }
  }
  if (!fixedVer && finding?.evidence) {
    for (const ev of finding.evidence) {
      if (ev?.raw_data?.fixed_version) {
        fixedVer = ev.raw_data.fixed_version;
        break;
      }
      if (ev?.raw_data?.fixed) {
        fixedVer = ev.raw_data.fixed;
        break;
      }
    }
  }

  const fixedStr = typeof fixedVer === "string" ? fixedVer.trim() : String(fixedVer || "").trim();
  if (!fixedStr || fixedStr.toLowerCase() === "latest" || fixedStr.includes("patched_version")) {
    if (ecosystem === "npm") {
      return `// package.json mitigation for ${pkgName}\n// No verified upstream fixed release available yet (Disputed / Unpatched advisory)\n// Monitor vendor disclosures or audit reachability of vulnerable methods`;
    } else if (ecosystem === "golang") {
      return `// go.mod mitigation for ${pkgName}\n// No verified upstream fixed release available yet`;
    } else if (ecosystem === "cargo") {
      return `# Cargo.toml mitigation for ${pkgName}\n# No verified upstream fixed release available yet`;
    } else {
      return `# requirements.txt mitigation for ${pkgName}\n# No verified upstream fixed release available yet (Disputed / Unpatched advisory)\n# Audit vendor disclosures or evaluate alternative library`;
    }
  }

  if (ecosystem === "npm") {
    const npmVer = (fixedStr.startsWith(">=") || fixedStr.startsWith("^") || fixedStr.startsWith("~"))
      ? fixedStr
      : `^${fixedStr}`;
    return `// package.json - Update in dependencies or overrides:\n"dependencies": {\n  "${pkgName}": "${npmVer}"\n},\n"overrides": {\n  "${pkgName}": "${npmVer}"\n}`;
  } else if (ecosystem === "golang") {
    const goVer = fixedStr.startsWith("v") ? fixedStr : `v${fixedStr}`;
    return `// go.mod directive & terminal command:\n// Run in terminal: go get ${pkgName}@${goVer} && go mod tidy\nrequire (\n  ${pkgName} ${goVer}\n)`;
  } else if (ecosystem === "cargo") {
    return `# Cargo.toml dependencies:\n[dependencies]\n${pkgName} = "${fixedStr}"\n# Or run: cargo update -p ${pkgName} --precise ${fixedStr}`;
  } else {
    // Python / pypi default
    const pipVer = (fixedStr.startsWith(">=") || fixedStr.startsWith("=="))
      ? fixedStr
      : `>=${fixedStr}`;
    return `# requirements.txt pin\n${pkgName}${pipVer}  # pinned by SupplyGraph`;
  }
}

/**
 * Aggregates raw findings into structured component packages with authoritative advisory metadata.
 */
export function aggregateComponentPackages(scanData: any): ComponentRemediationPackage[] {
  const findings: any[] = scanData?.findings || [];
  const components: any[] = scanData?.components || scanData?.sbom?.components || [];
  const packageMap: Record<string, ComponentRemediationPackage> = {};

  const compIndex: Record<string, any> = {};
  components.forEach((c) => {
    if (c.name) compIndex[c.name.toLowerCase()] = c;
    if (c.purl) compIndex[c.purl.toLowerCase()] = c;
    if (c.bom_ref) compIndex[c.bom_ref.toLowerCase()] = c;
  });

  findings.forEach((f: any) => {
    if (f.finding_type === "VULNERABLE" || (f.origin_candidate && f.origin_candidate.includes("@"))) {
      const { pkgName, version, ecosystem, key } = getFindingPackage(f);
      if (!packageMap[key]) {
        const comp = compIndex[pkgName.toLowerCase()] || compIndex[f.origin_candidate?.toLowerCase()] || null;
        let scope: DependencyScope = "UNKNOWN";
        let discrepancy: string | undefined = undefined;

        if (comp) {
          if (comp.is_direct && comp.is_transitive) {
            scope = "MIXED";
          } else if (comp.is_direct) {
            scope = "DIRECT";
          } else if (comp.is_transitive) {
            scope = "TRANSITIVE";
          }
          if (comp.audit_discrepancy) {
            discrepancy = comp.audit_discrepancy;
          }
        }

        packageMap[key] = {
          key,
          pkgName,
          installedVersion: version,
          ecosystem,
          scope,
          declaredIn: comp?.declared_in,
          discrepancy,
          isDev: comp?.is_dev,
          findings: [],
          highestSeverity: "LOW",
          advisories: [],
          dependencyPaths: [],
          resolution: {
            rawFixed: "",
            cleanVersion: "",
            category: "NO_VERIFIED_FIX",
            isMajorUpgrade: false,
            majorDiff: 0,
            explanation: "",
          },
        };
      }

      packageMap[key].findings.push(f);

      if (f.origin_candidate && !packageMap[key].dependencyPaths?.includes(f.origin_candidate)) {
        packageMap[key].dependencyPaths?.push(f.origin_candidate);
      }
      if (f.dependency_path && !packageMap[key].dependencyPaths?.includes(f.dependency_path)) {
        packageMap[key].dependencyPaths?.push(f.dependency_path);
      }

      const currentSev = f.severity?.toUpperCase() || "LOW";
      const sevOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
      const groupSevIdx = sevOrder.indexOf(packageMap[key].highestSeverity);
      const curSevIdx = sevOrder.indexOf(currentSev);
      if (curSevIdx !== -1 && (groupSevIdx === -1 || curSevIdx < groupSevIdx)) {
        packageMap[key].highestSeverity = currentSev;
      }

      const cveMatch = f.title?.match(/(GHSA-[a-z0-9-]+|CVE-\d{4}-\d+|GO-\d{4}-\d+|PYSEC-\d{4}-\d+)/i);
      const advId = cveMatch ? cveMatch[1] : (f.id || `FINDING-${packageMap[key].advisories.length + 1}`);
      if (!packageMap[key].advisories.some(a => a.id === advId)) {
        let advFix = "";
        let affRange = "";
        if (f.recommendations?.[0]?.fixed_version) advFix = f.recommendations[0].fixed_version;
        else if (f.evidence) {
          for (const ev of f.evidence) {
            if (ev?.raw_data?.fixed_version) { advFix = ev.raw_data.fixed_version; break; }
            if (ev?.raw_data?.fixed) { advFix = ev.raw_data.fixed; break; }
            if (ev?.raw_data?.affected_range) { affRange = ev.raw_data.affected_range; }
          }
        }
        packageMap[key].advisories.push({
          id: advId,
          title: f.title || "Vulnerability Advisory",
          severity: f.severity || "MEDIUM",
          description: f.description,
          fixedVersion: advFix,
          affectedRange: affRange,
        });
      }
    }
  });

  return Object.values(packageMap).map((pkg) => {
    const candidateFixes: string[] = [];
    let conflictingSources = false;
    let sourceUnavailable = false;

    pkg.findings.forEach((f) => {
      if (f.conflicting_sources) conflictingSources = true;
      if (f.source_unavailable) sourceUnavailable = true;

      if (f.recommendations) {
        f.recommendations.forEach((r: any) => {
          if (r?.fixed_version) candidateFixes.push(r.fixed_version);
        });
      }
      if (f.evidence) {
        f.evidence.forEach((e: any) => {
          if (e?.raw_data?.fixed_version) candidateFixes.push(e.raw_data.fixed_version);
          if (e?.raw_data?.fixed) candidateFixes.push(e.raw_data.fixed);
        });
      }
    });

    const resolution = resolveVersionWithConfidence(
      pkg.installedVersion,
      candidateFixes,
      {
        advisories: pkg.advisories,
        conflictingSources,
        sourceUnavailable,
      }
    );

    return {
      ...pkg,
      resolution,
    };
  });
}

/**
 * Generates an evidence-grounded Master AI Fix Prompt conforming to the 5-phase protocol,
 * structured 3-tier modification scope policy, targeted package-manager operations, and honest reporting.
 */
export function generateMasterAIFixPrompt(scanData: any, options: PromptGeneratorOptions = {}): string {
  if (!scanData) return "";
  const repo = scanData?.scan?.repository_url || "Target Repository / Local Project";
  const findings = scanData?.findings || [];
  const codeReviews = scanData?.code_reviews || [];
  const blastRadius = scanData?.scan?.blast_radius_score || 0;
  const packagesList = aggregateComponentPackages(scanData);

  const { nodePm, pythonPm, hasGo, hasCargo, workspaces, manifestPaths, conflicts } = detectPackageManagers(scanData);

  // Compute precise distinct inventory counts
  const totalRawFindings = findings.length;
  const uniqueAdvisories = new Set<string>();
  packagesList.forEach(pkg => {
    pkg.advisories.forEach(adv => uniqueAdvisories.add(adv.id));
  });
  const totalUniqueAdvisories = uniqueAdvisories.size;
  const totalAffectedComponents = packagesList.length;

  const uniquePaths = new Set<string>();
  packagesList.forEach(pkg => {
    if (pkg.declaredIn) uniquePaths.add(pkg.declaredIn);
    pkg.dependencyPaths?.forEach(p => uniquePaths.add(p));
  });
  const totalAffectedPaths = Math.max(uniquePaths.size, manifestPaths.length, 1);

  const npmPackages = packagesList.filter((p) => p.ecosystem === "npm");
  const pypiPackages = packagesList.filter((p) => p.ecosystem === "pypi");
  const goPackages = packagesList.filter((p) => p.ecosystem === "golang");
  const cargoPackages = packagesList.filter((p) => p.ecosystem === "cargo");
  const cicdFindings = findings.filter((f: any) => f.finding_type === "CICD_RISK" || f.title?.includes("CI/CD"));
  const astFindings = findings.filter((f: any) => f.finding_type === "AST" || f.title?.includes("AST") || f.finding_type === "SUSPICIOUS");

  const backendCodeReviews = codeReviews.filter((cr: any) =>
    !cr.file_path?.endsWith('.yml') &&
    !cr.file_path?.endsWith('.yaml') &&
    !cr.title?.includes('CI/CD') &&
    !cr.file_path?.includes('.github/workflows')
  );

  const cicdCodeReviews = codeReviews.filter((cr: any) =>
    cr.file_path?.endsWith('.yml') ||
    cr.file_path?.endsWith('.yaml') ||
    cr.title?.includes('CI/CD') ||
    cr.file_path?.includes('.github/workflows')
  );

  function getLanguageFromPath(filePath: string): string {
    const ext = filePath.split('.').pop()?.toLowerCase() || '';
    if (ext === 'py') return 'python';
    if (ext === 'ts' || ext === 'tsx') return 'typescript';
    if (ext === 'js' || ext === 'jsx') return 'javascript';
    if (ext === 'go') return 'go';
    if (ext === 'rs') return 'rust';
    if (ext === 'json') return 'json';
    if (ext === 'yml' || ext === 'yaml') return 'yaml';
    return 'text';
  }

  let p = "";

  // 1. Role and Objective
  p += `# AI SECURITY REMEDIATION TASK: Complete Codebase Security Hardening\n\n`;
  p += `You are an expert Principal Application Security Engineer, Software Supply-Chain Specialist, and Senior Full-Stack Architect.\n`;
  p += `SupplyGraph has conducted an evidence-bounded supply-chain security audit on this project and identified security vulnerabilities, outdated dependencies, and CI/CD supply-chain risks.\n`;
  p += `Your objective is to remediate confirmed security vulnerabilities using minimal, targeted, evidence-grounded modifications while preserving existing application functionality and minimizing regressions.\n\n`;

  // 2. Strict Execution Rules with Structured 3-Tier Modification Scope
  p += `### STRICT EXECUTION RULES FOR AI ASSISTANTS (Antigravity / Cursor / Claude / ChatGPT / Copilot):\n`;
  p += `1. **Preserve Application Functionality**: Maintain existing features, public API contracts, database schemas, business logic, routing, and authentication controls.\n`;
  p += `2. **Honest Engineering Boundaries**:\n`;
  p += `   - Do NOT promise "zero regressions", "100% backward compatibility", "100% vulnerability elimination", or "guaranteed one-shot execution". These are goals, not guaranteed facts.\n`;
  p += `   - If a major upgrade is required to fix an advisory, conduct breaking-change compatibility analysis and review upstream migration notes.\n`;
  p += `   - If test suites are missing or cannot run in the execution environment, clearly report the resulting uncertainty in the final report.\n`;
  p += `   - If the task exceeds the available execution budget, apply changes in controlled batches and reconcile every original finding before declaring completion.\n`;
  p += `3. **No Fabricated Evidence**: Never invent package versions, advisory IDs, commit SHAs, or upstream fix claims.\n`;
  p += `4. **Structured 3-Tier Modification Scope Policy**:\n`;
  p += `   - **Category A — Expected Remediation Files**:\n`;
  p += `     - Dependency manifests (\`package.json\`, \`requirements.txt\`, \`pyproject.toml\`, \`go.mod\`, \`Cargo.toml\`).\n`;
  p += `     - Lockfiles (\`package-lock.json\`, \`pnpm-lock.yaml\`, \`yarn.lock\`, \`poetry.lock\`, \`uv.lock\`, \`Pipfile.lock\`, \`go.sum\`, \`Cargo.lock\`).\n`;
  p += `     - Workflow manifests (\`.github/workflows/*.yml\`, \`.github/workflows/*.yaml\`).\n`;
  p += `     - Application files with explicit AST or security code-review patches identified by SupplyGraph in Section 3.\n`;
  p += `   - **Category B — Necessary Compatibility Files (Call-Sites)**:\n`;
  p += `     - Application source files that call or import upgraded dependencies where public APIs, function signatures, or classes changed across versions.\n`;
  p += `     - Modification of Category B files is **PERMITTED ONLY when strictly necessary** to maintain compatibility with a remediated dependency and prevent runtime errors (\`ImportError\`, \`AttributeError\`, \`TypeError\`).\n`;
  p += `     - The AI assistant **MUST document every modified Category B file** and explain the specific breaking API change in the Phase E final report.\n`;
  p += `   - **Category C — Unrelated Project Files (STRICTLY PROHIBITED)**:\n`;
  p += `     - Unrelated features, business logic, public API route contracts, database schemas, styling, or formatting churn.\n`;
  p += `     - Modification of Category C files is strictly prohibited unless explicitly requested by the user.\n\n`;

  // 3. Repository Context & Evidence Metadata
  p += `## 1. REPOSITORY CONTEXT & AUDIT INVENTORY METADATA\n`;
  p += `- **Target Project / Repository**: \`${repo}\`\n`;
  if (options.targetBranch) p += `- **Target Branch**: \`${options.targetBranch}\`\n`;

  // Repository Identity Validation
  if (options.expectedRepositoryUrl && scanData?.scan?.repository_url) {
    const normExpected = options.expectedRepositoryUrl.trim().toLowerCase().replace(/\.git$/, "");
    const normActual = scanData.scan.repository_url.trim().toLowerCase().replace(/\.git$/, "");
    if (normExpected !== normActual) {
      p += `> ⚠️ **REPOSITORY IDENTITY MISMATCH DETECTED**:\n`;
      p += `> The audit data originates from \`${scanData.scan.repository_url}\`, but the active target repository is \`${options.expectedRepositoryUrl}\`.\n`;
      p += `> Verify audit origin before executing changes to avoid applying mismatched security configurations.\n\n`;
    }
  }

  p += `- **Total Raw Security Findings Reported**: ${totalRawFindings}\n`;
  p += `- **Unique Security Advisories (CVE / GHSA / OSV)**: ${totalUniqueAdvisories}\n`;
  p += `- **Unique Affected Packages / Components**: ${totalAffectedComponents}\n`;
  p += `- **Affected Dependency Paths / Manifest Locations**: ${totalAffectedPaths}\n`;
  p += `- **CI/CD Pipeline Security Findings**: ${codeReviews.length + cicdFindings.length}\n`;
  p += `- **Supply Chain Blast Radius Score**: ${blastRadius}/100\n`;
  p += `- **Authoritative Intelligence Sources**: OSV.dev (Open Source Vulnerabilities), GitHub Advisory Database (GHSA), NVD/CVE, static AST analysis, OpenSSF workflow audit.\n\n`;

  p += `> ⚠️ **INVENTORY COUNTING RULE**: Raw finding counts, unique advisories, affected packages, and dependency paths are distinct metrics and must NOT be treated as interchangeable. An audit reporting ${totalRawFindings} raw findings may represent ${totalUniqueAdvisories} unique advisories across ${totalAffectedComponents} packages. Every raw finding must be tracked and reconciled in Phase E.\n\n`;

  if (conflicts && conflicts.length > 0) {
    p += `> ⚠️ **CONFLICTING PACKAGE-MANAGER METADATA DETECTED**:\n`;
    conflicts.forEach(c => {
      p += `> - ${c}\n`;
    });
    p += `> **Recommendation**: Reconcile redundant lockfiles and execute only the authoritative package manager designated for this project.\n\n`;
  }

  if (workspaces.isWorkspace) {
    p += `### Monorepo / Multi-Manifest Workspace Detected:\n`;
    p += `- **Workspace Package Manager**: \`${workspaces.packageManager}\`\n`;
    p += `- **Manifest Files Found**:\n`;
    workspaces.manifests.forEach(m => {
      p += `  - \`${m}\`\n`;
    });
    p += `\n`;
  }

  // 4. Staged 5-Phase Remediation Protocol
  p += `## 2. STAGED REMEDIATION PROTOCOL (STRICT EXECUTION SEQUENCE)\n`;
  p += `You MUST follow this 5-phase engineering protocol to ensure systematic verification and prevent broken builds:\n\n`;

  p += `### PHASE A — ESTABLISH BASELINE\n`;
  p += `1. **Git State Inspection**: Check \`git status\` and preserve any uncommitted user work.\n`;
  p += `2. **Repository & Tool Discovery**: Detect active package manager (\`${nodePm}\`, \`${pythonPm}\`, \`go\`, \`cargo\`), Node.js/Python runtimes, lockfiles, and workspace configuration.\n`;
  p += `3. **Audit Inventory Reading**: Read the complete audit inventory below. Distinguish raw findings, unique advisories, affected packages, and affected dependency paths.\n`;
  p += `4. **Baseline Test Execution**: Run existing test suites (\`npm test\`, \`pytest\`, \`go test\`) and record initial passing/failing status before editing any file.\n\n`;

  p += `### PHASE B — PLAN REMEDIATION\n`;
  p += `1. **Inventory Mapping**: Review Section 3 below. Map every finding to its exact manifest (\`package.json\`, \`requirements.txt\`, \`go.mod\`) or workflow file.\n`;
  p += `2. **Scope Distinction**: Distinguish direct dependencies from transitive sub-dependencies. Do NOT add transitive packages into direct manifest dependencies unless justified.\n`;
  p += `3. **Breaking Change Assessment**: Review all packages flagged with \`COMPATIBILITY_REVIEW_REQUIRED\` and evaluate migration requirements before applying.\n`;
  p += `4. **Grouping & Batching**: Group compatible changes. If modifying more than 15 packages, apply changes in staged batches.\n`;
  p += `5. **Manual Investigation Planning**: Identify findings requiring vendor review or manual investigation (unpatched advisories or missing fixed versions).\n\n`;

  p += `### PHASE C — IMPLEMENT CHANGES\n`;
  p += `1. **Surgical Modifications**: Apply the smallest suitable version bump or code patch that eliminates the vulnerability.\n`;
  p += `2. **Preserve Contracts**: Do NOT modify unrelated features, business logic, public API contracts, database schemas, or authentication/authorization rules (Category C).\n`;
  p += `3. **Category B Call-Sites**: If an upgraded library introduces breaking API changes, modify the affected call-sites in Category B and record each modification.\n`;
  p += `4. **Lockfile Synchronization**: Update manifests and regenerate lockfiles synchronously using the detected package manager with targeted commands.\n`;
  p += `5. **No Suppressions**: Do NOT delete tests, weaken assertion thresholds, or suppress linting/security errors to achieve a passing status.\n\n`;

  p += `### PHASE D — VERIFY\n`;
  p += `1. **Manifest & Lockfile Integrity**: Validate that manifests are syntactically valid and lockfiles resolve cleanly.\n`;
  p += `2. **Run Full Test Suite**: Execute project test suites and verify that no functional regressions or broken behavior were introduced compared to Phase A baseline.\n`;
  p += `3. **Production Build & Lint**: Run build commands (\`npm run build\`, etc.) to confirm packaging and compilation succeed.\n`;
  p += `4. **API Contract & Workflow Tests**: Test affected endpoints and workflows.\n`;
  p += `5. **Post-Remediation Rescan**: Re-run vulnerability scanning or review dependency tree to verify advisories are closed.\n`;
  p += `6. **Diff Audit**: Review \`git diff\` to ensure changes are strictly bounded to Category A and documented Category B files.\n\n`;

  p += `### PHASE E — REPORT\n`;
  p += `Produce a structured final reconciliation report adhering to the template in Section 6.\n\n`;

  p += `============================================================\n\n`;

  // 5. Finding-by-Finding Remediation Inventory
  p += `## 3. EVIDENCE-BASED REMEDIATION INSTRUCTIONS\n\n`;

  let stepNum = 1;

  // Node.js / npm Section
  if (npmPackages.length > 0) {
    p += `### 3.${stepNum} JavaScript / Node.js Dependencies (\`package.json\`)\n`;
    p += `- **Detected Package Manager**: \`${nodePm}\`\n`;
    if (workspaces.isWorkspace) {
      p += `- **Workspace Manifests**: ${workspaces.manifests.map(m => `\`${m}\``).join(", ")}\n`;
    } else {
      p += `- **Target File(s)**: Locate \`package.json\` in project root or workspace directories (e.g., \`frontend/package.json\`).\n`;
    }
    p += `\n`;

    const directPackages = npmPackages.filter(pkg => pkg.scope === "DIRECT" || pkg.scope === "UNKNOWN");
    const transitivePackages = npmPackages.filter(pkg => pkg.scope === "TRANSITIVE" || pkg.scope === "MIXED" || pkg.scope === "DIRECT_AND_TRANSITIVE");

    if (directPackages.length > 0) {
      p += `#### A. Direct Dependencies to Update:\n`;
      p += `Update the version constraint in \`"dependencies"\` or \`"devDependencies"\`:\n\n`;
      p += `\`\`\`json\n{\n  "dependencies": {\n`;
      directPackages.forEach((pkg, idx) => {
        const comma = idx < directPackages.length - 1 ? "," : "";
        const constraint = pkg.resolution.npmConstraint || `^${pkg.resolution.cleanVersion}`;
        p += `    "${pkg.pkgName}": "${constraint}"${comma}\n`;
      });
      p += `  }\n}\n\`\`\`\n\n`;
    }

    if (transitivePackages.length > 0 || npmPackages.length > 0) {
      p += `#### B. Transitive Sub-Dependencies & Overrides:\n`;
      p += `> **Rule**: Do NOT add transitive dependencies into root \`dependencies\`. Use native overrides/resolutions to constrain nested packages:\n\n`;
      if (nodePm === "pnpm") {
        p += `For **pnpm**, add to \`pnpm.overrides\` in root \`package.json\`:\n`;
        p += `\`\`\`json\n{\n  "pnpm": {\n    "overrides": {\n`;
        npmPackages.forEach((pkg, idx) => {
          const comma = idx < npmPackages.length - 1 ? "," : "";
          p += `      "${pkg.pkgName}": "${pkg.resolution.npmConstraint || `^${pkg.resolution.cleanVersion}`}"${comma}\n`;
        });
        p += `    }\n  }\n}\n\`\`\`\n\n`;
      } else if (nodePm === "yarn") {
        p += `For **Yarn**, add to \`resolutions\` in root \`package.json\`:\n`;
        p += `\`\`\`json\n{\n  "resolutions": {\n`;
        npmPackages.forEach((pkg, idx) => {
          const comma = idx < npmPackages.length - 1 ? "," : "";
          p += `    "${pkg.pkgName}": "${pkg.resolution.npmConstraint || `^${pkg.resolution.cleanVersion}`}"${comma}\n`;
        });
        p += `  }\n}\n\`\`\`\n\n`;
      } else {
        p += `For **npm (v8.3+)**, add to \`overrides\` in root \`package.json\`:\n`;
        p += `\`\`\`json\n{\n  "overrides": {\n`;
        npmPackages.forEach((pkg, idx) => {
          const comma = idx < npmPackages.length - 1 ? "," : "";
          p += `    "${pkg.pkgName}": "${pkg.resolution.npmConstraint || `^${pkg.resolution.cleanVersion}`}"${comma}\n`;
        });
        p += `  }\n}\n\`\`\`\n\n`;
      }
    }

    p += `#### C. Component Details & Vulnerability Evidence:\n`;
    npmPackages.forEach((pkg) => {
      const upgradeTag = pkg.resolution.category === "COMPATIBILITY_REVIEW_REQUIRED"
        ? " ⚠️ [COMPATIBILITY REVIEW REQUIRED - MAJOR UPGRADE]"
        : "";
      p += `- **\`${pkg.pkgName}@${pkg.installedVersion || "installed"}\`** [${pkg.highestSeverity}] (${pkg.findings.length} raw finding(s), ${pkg.advisories.length} unique advisory(s))${upgradeTag}\n`;
      p += `  - **Recommendation State**: \`${pkg.resolution.category}\`\n`;
      p += `  - **Scope**: ${pkg.scope} dependency${pkg.declaredIn ? ` (declared in \`${pkg.declaredIn}\`)` : ""}\n`;
      if (pkg.discrepancy) {
        p += `  - **Audit Discrepancy**: ${pkg.discrepancy}\n`;
      }
      p += `  - **Target Version**: \`${pkg.resolution.cleanVersion || "Manual Investigation Required"}\`\n`;
      p += `  - **Remediation Note**: ${pkg.resolution.explanation}\n`;
      p += `  - **Advisories Addressed**: ${pkg.advisories.map(a => a.id).slice(0, 8).join(", ")}${pkg.advisories.length > 8 ? ` +${pkg.advisories.length - 8} more` : ""}\n`;
      if (pkg.resolution.category === "COMPATIBILITY_REVIEW_REQUIRED") {
        p += `  - **Compatibility Assessment**: Major version bump (${pkg.installedVersion} -> ${pkg.resolution.cleanVersion}). Audit package changelog for breaking changes before committing.\n`;
      }
    });

    p += `\n> **Targeted Lockfile Synchronization Commands**:\n`;
    p += `\`\`\`bash\n`;
    if (nodePm === "pnpm") {
      p += `# Targeted update for pnpm:\n`;
      directPackages.forEach(pkg => {
        p += `pnpm update ${pkg.pkgName}@${pkg.resolution.cleanVersion}\n`;
      });
      p += `# Or synchronize lockfile cleanly:\npnpm install\n`;
    } else if (nodePm === "yarn") {
      p += `# Targeted update for Yarn:\n`;
      directPackages.forEach(pkg => {
        p += `yarn up ${pkg.pkgName}@${pkg.resolution.cleanVersion}\n`;
      });
      p += `# Or synchronize lockfile cleanly:\nyarn install\n`;
    } else if (nodePm === "bun") {
      p += `# Targeted update for bun:\n`;
      directPackages.forEach(pkg => {
        p += `bun add ${pkg.pkgName}@${pkg.resolution.cleanVersion}\n`;
      });
      p += `bun install\n`;
    } else {
      p += `# Targeted lockfile update for npm (preserves unrelated dependencies):\n`;
      directPackages.forEach(pkg => {
        p += `npm install ${pkg.pkgName}@${pkg.resolution.cleanVersion} --package-lock-only\n`;
      });
      p += `# Or synchronize lockfile cleanly:\nnpm install --package-lock-only\n`;
    }
    p += `\`\`\`\n\n`;
    stepNum++;
  }

  // Python / PyPI Section
  if (pypiPackages.length > 0) {
    p += `### 3.${stepNum} Python Dependencies (\`requirements.txt\` / \`pyproject.toml\`)\n`;
    p += `- **Detected Package Tool**: \`${pythonPm}\`\n`;
    p += `- **Target File(s)**: \`requirements.txt\`, \`pyproject.toml\`, or backend manifests.\n\n`;

    const verifiedPypi = pypiPackages.filter(p => p.resolution.category !== "NO_VERIFIED_FIX" && p.resolution.category !== "MANUAL_INVESTIGATION_REQUIRED");
    const unverifiedPypi = pypiPackages.filter(p => p.resolution.category === "NO_VERIFIED_FIX" || p.resolution.category === "MANUAL_INVESTIGATION_REQUIRED");

    if (verifiedPypi.length > 0) {
      p += `#### A. PEP 440 Pinning Constraints:\n`;
      p += `\`\`\`text\n`;
      verifiedPypi.forEach((pkg) => {
        p += `${pkg.pkgName}${pkg.resolution.pep440Constraint}  # Pinned by SupplyGraph (${pkg.findings.length} raw finding(s), ${pkg.advisories.length} unique advisory(s))\n`;
      });
      p += `\`\`\`\n\n`;
    }

    if (unverifiedPypi.length > 0) {
      p += `#### B. Advisories Requiring Manual Investigation (No Verified Upstream Release):\n`;
      unverifiedPypi.forEach((pkg) => {
        p += `- **\`${pkg.pkgName}@${pkg.installedVersion}\`**: ${pkg.resolution.explanation}\n`;
        p += `  - Action: Inspect upstream advisory disclosures (${pkg.advisories.map(a => a.id).join(", ")}). Check whether vulnerable methods are reachable in application code, or evaluate alternative packages.\n`;
      });
      p += `\n`;
    }

    p += `#### C. Component Details & Vulnerability Evidence:\n`;
    pypiPackages.forEach((pkg) => {
      const upgradeTag = (pkg.resolution.category === "COMPATIBILITY_REVIEW_REQUIRED" || pkg.resolution.isMajorUpgrade)
        ? " ⚠️ [COMPATIBILITY REVIEW REQUIRED - MAJOR UPGRADE]"
        : "";
      p += `- **\`${pkg.pkgName}@${pkg.installedVersion || "installed"}\`** [${pkg.highestSeverity}] (${pkg.findings.length} raw finding(s), ${pkg.advisories.length} unique advisory(s))${upgradeTag}\n`;
      p += `  - **Recommendation State**: \`${pkg.resolution.category}\`\n`;
      p += `  - **Scope**: ${pkg.scope} dependency${pkg.declaredIn ? ` (declared in \`${pkg.declaredIn}\`)` : ""}\n`;
      if (pkg.discrepancy) {
        p += `  - **Audit Discrepancy**: ${pkg.discrepancy}\n`;
      }
      p += `  - **Target Version**: \`${pkg.resolution.pep440Constraint || "Manual Investigation Required"}\`\n`;
      p += `  - **Remediation Note**: ${pkg.resolution.explanation}\n`;
      p += `  - **Advisories Addressed**: ${pkg.advisories.map(a => a.id).slice(0, 8).join(", ")}${pkg.advisories.length > 8 ? ` +${pkg.advisories.length - 8} more` : ""}\n`;
      if (pkg.resolution.category === "COMPATIBILITY_REVIEW_REQUIRED" || pkg.resolution.isMajorUpgrade) {
        p += `  - **Compatibility Assessment**: Major version bump (${pkg.installedVersion} -> ${pkg.resolution.cleanVersion}). Audit package changelog for breaking changes before committing.\n`;
      }
    });

    p += `\n> **Targeted Lockfile / Environment Synchronization Commands**:\n`;
    p += `> **Note**: Never assume that \`pip install\` automatically regenerates a lockfile. For Poetry, Pipenv, or uv, run the dedicated lock command:\n`;
    p += `\`\`\`bash\n`;
    if (pythonPm === "poetry") {
      p += `# Targeted update for Poetry:\n`;
      verifiedPypi.forEach(pkg => {
        p += `poetry update ${pkg.pkgName}\n`;
      });
      p += `# Or lockfile synchronization:\npoetry lock --no-update && poetry install\n`;
    } else if (pythonPm === "pipenv") {
      p += `# Targeted update for Pipenv:\n`;
      verifiedPypi.forEach(pkg => {
        p += `pipenv update ${pkg.pkgName}\n`;
      });
      p += `# Or lockfile synchronization:\npipenv lock && pipenv install\n`;
    } else if (pythonPm === "uv") {
      p += `# Targeted update for uv:\n`;
      verifiedPypi.forEach(pkg => {
        p += `uv lock --upgrade-package ${pkg.pkgName}\n`;
      });
      p += `# Or environment sync:\nuv lock && uv sync\n`;
    } else {
      p += `# Update pinned constraints in requirements.txt first, then run targeted install:\n`;
      verifiedPypi.forEach(pkg => {
        p += `pip install "${pkg.pkgName}${pkg.resolution.pep440Constraint}"\n`;
      });
      p += `# Synchronize requirements.txt (preserving unrelated dependencies):\npip install -r requirements.txt\n`;
      p += `# ⚠️ CAUTION: Do NOT run \`pip install -r requirements.txt --upgrade\` as it forces upgrades on unrelated packages.\n`;
      p += `# Note: Plain pip does not generate a reproducible lockfile.\n`;
    }
    p += `\`\`\`\n\n`;
    stepNum++;
  }

  // Golang Section
  if (goPackages.length > 0) {
    p += `### 3.${stepNum} Golang Modules (\`go.mod\`)\n`;
    p += `- **Target File**: \`go.mod\`\n\n`;
    p += `\`\`\`bash\n`;
    goPackages.forEach((pkg) => {
      const ver = pkg.resolution.cleanVersion ? (pkg.resolution.cleanVersion.startsWith("v") ? pkg.resolution.cleanVersion : `v${pkg.resolution.cleanVersion}`) : "latest";
      p += `go get ${pkg.pkgName}@${ver}\n`;
    });
    p += `go mod tidy\n`;
    p += `\`\`\`\n\n`;
    stepNum++;
  }

  // Cargo Section
  if (cargoPackages.length > 0) {
    p += `### 3.${stepNum} Rust Dependencies (\`Cargo.toml\`)\n`;
    p += `- **Target File**: \`Cargo.toml\`\n\n`;
    p += `\`\`\`toml\n[dependencies]\n`;
    cargoPackages.forEach((pkg) => {
      p += `${pkg.pkgName} = "${pkg.resolution.cleanVersion}"\n`;
    });
    p += `\`\`\`\n\n`;
    p += `Update lockfile with: \`cargo update\n`;
    cargoPackages.forEach((pkg) => {
      if (pkg.resolution.cleanVersion) {
        p += `cargo update -p ${pkg.pkgName} --precise ${pkg.resolution.cleanVersion}\n`;
      }
    });
    p += `\`\n\n`;
    stepNum++;
  }

  // Backend & Application Source Code Fixes
  if (backendCodeReviews.length > 0) {
    p += `### 3.${stepNum} Backend & Application Source Code Vulnerability Fixes (AST & Static Code Review)\n`;
    p += `> **CRITICAL**: The following source code vulnerabilities and bugs were discovered inside the project's application files. You MUST apply these surgical code patches to prevent runtime crashes, remote code execution, and data leakage:\n\n`;

    backendCodeReviews.forEach((cr: any, idx: number) => {
      const lang = getLanguageFromPath(cr.file_path);
      p += `#### Backend Patch #${idx + 1}: ${cr.title} [${cr.severity}] (${cr.category || "Security Vulnerability"})\n`;
      p += `- **Target File**: \`${cr.file_path}\` (around line ${cr.line_number})\n`;
      p += `- **Issue Explanation**: ${cr.error_explanation}\n`;
      if (cr.unified_diff) {
        p += `\`\`\`diff\n${cr.unified_diff}\n\`\`\`\n\n`;
      } else if (cr.corrected_code) {
        p += `Replace:\n\`\`\`${lang}\n${cr.buggy_code}\n\`\`\`\nWith:\n\`\`\`${lang}\n${cr.corrected_code}\n\`\`\`\n\n`;
      }
    });
    stepNum++;
  }

  // CI/CD Workflows Section
  p += `### 3.${stepNum} CI/CD Pipeline Security Hardening (\`.github/workflows/\`)\n`;
  if (cicdCodeReviews.length > 0) {
    cicdCodeReviews.forEach((cr: any, idx: number) => {
      p += `#### CI/CD Patch #${idx + 1}: ${cr.title} [${cr.severity}]\n`;
      p += `- **File**: \`${cr.file_path}\` (around line ${cr.line_number})\n`;
      p += `- **Security Rule**: ${cr.error_explanation}\n`;
      if (cr.unified_diff) {
        p += `\`\`\`diff\n${cr.unified_diff}\n\`\`\`\n\n`;
      } else if (cr.corrected_code) {
        p += `Replace:\n\`\`\`yaml\n${cr.buggy_code}\n\`\`\`\nWith:\n\`\`\`yaml\n${cr.corrected_code}\n\`\`\`\n\n`;
      }
    });
  } else if (cicdFindings.length > 0) {
    cicdFindings.forEach((cf: any, idx: number) => {
      p += `#### CI/CD Advisory #${idx + 1}: ${cf.title} [${cf.severity}]\n`;
      p += `- **Description**: ${cf.description}\n`;
      const snippet = buildLockfileSnippet(cf);
      if (snippet) p += `\`\`\`yaml\n${snippet}\n\`\`\`\n\n`;
    });
  } else {
    p += `**Scope of performed CI/CD checks**:\n`;
    p += `1. Immutable commit SHA pinning for third-party actions (\`uses:\` directives).\n`;
    p += `2. Least-privilege permissions analysis (checks for blanket \`write-all\` permissions).\n`;
    p += `3. Script injection vulnerability detection in \`run:\` steps (untrusted \`github.event\` context variables).\n`;
    p += `4. Insecure download-and-execute patterns (\`curl | bash\`).\n\n`;
    p += `- **Result**: 0 actionable risks detected across audited workflow files.\n`;
    p += `- **Note**: This audit evaluates static workflow configurations. Self-hosted runner isolation, repository secret handling, and upstream action implementation integrity require separate operational assessment.\n\n`;
  }
  stepNum++;

  // Call-Site Dependency Compatibility & Category B Refactoring
  p += `### 3.${stepNum} Call-Site Dependency Audit & API Compatibility Refactoring (Category B)\n`;
  p += `> ⚠️ **WHY BACKENDS BREAK ON DEPENDENCY UPDATES (CATEGORY B COMPATIBILITY AUDIT)**:\n`;
  p += `> Bumping package versions in Category A manifests changes the installed library, but **DOES NOT update the application code calling it**. If the new version deprecates or removes an API, the backend will crash at startup with \`ImportError\`, \`AttributeError\`, or \`TypeError\`.\n`;
  p += `>\n`;
  p += `> **EXECUTION RULES FOR CATEGORY B MODIFICATIONS**:\n`;
  p += `> 1. You are authorized to modify **Category B files** (call-sites) ONLY when required to maintain compatibility with an upgraded dependency.\n`;
  p += `> 2. Search every source file in the project for calls to the upgraded dependencies:\n`;
  p += `>    - Python: Run \`grep -rn "import <package>" .\` and \`grep -rn "from <package>" .\`\n`;
  p += `>    - Node.js: Run \`grep -rn "require('<package>')" .\` and \`grep -rn "from '<package>'" .\`\n`;
  p += `> 3. Check for high-risk breaking change signatures:\n`;
  p += `>    - **Pillow (v10+ / v13+)**: \`Image.ANTIALIAS\` was removed. Replace with \`Image.Resampling.LANCZOS\`.\n`;
  p += `>    - **Pydantic (v1 -> v2)**: \`from pydantic import BaseSettings\` raises \`ImportError\`. Use \`from pydantic_settings import BaseSettings\`. Replace \`.dict()\` with \`.model_dump()\`. Replace \`@validator\` with \`@field_validator\`.\n`;
  p += `>    - **SQLAlchemy (v1.4 -> v2.0)**: Raw SQL strings in \`session.execute()\` must be wrapped with \`text("...")\` from \`sqlalchemy import text\`.\n`;
  p += `>    - **Requests & Urllib3**: Ensure \`verify=False\` is removed, and custom adapter connection pools match current syntax.\n`;
  p += `>    - **Next.js (v14 -> v15/v16)**: \`params\` and \`searchParams\` in Route Handlers and Pages must be awaited (\`const { id } = await params\`).\n`;
  p += `>    - **PyJWT / JSONWebToken**: Explicitly declare verification algorithms: \`jwt.decode(token, secret, algorithms=["HS256"])\`.\n`;
  p += `> 4. **Mandatory Documentation**: Every modified Category B file MUST be justified and listed in the Phase E report under "Category B Compatibility Modifications".\n`;
  p += `> 5. **Scope Extension Rule**: If new test or compilation evidence reveals another necessary file, extend scope narrowly and document the reason in the Phase E report.\n`;
  p += `> 6. **Prohibited Changes**: Do NOT modify Category C files (unrelated features, database schemas, styling).\n\n`;
  stepNum++;

  // AST / Application Code Section
  if (astFindings.length > 0) {
    p += `### 3.${stepNum} Additional AST Pattern Refactoring\n`;
    astFindings.forEach((af: any, idx: number) => {
      p += `#### Code Signal #${idx + 1}: ${af.title} [${af.severity}]\n`;
      p += `- **Finding Description**: ${af.description}\n`;
      p += `- **Required Refactoring**:\n`;
      p += `  1. Replace dynamic \`eval()\` or \`exec()\` with safe parsers (\`json.loads()\`, \`ast.literal_eval()\`).\n`;
      p += `  2. Avoid \`subprocess(..., shell=True)\`; always pass arguments as a structured array: \`subprocess.run(['cmd', 'arg1', 'arg2'])\`.\n`;
      p += `  3. Remove hardcoded credentials/secrets; load them exclusively via environment variables (\`os.environ.get(...)\` or \`process.env\`).\n\n`;
    });
    stepNum++;
  }

  // Safe Failure Handling Protocol
  p += `### 3.${stepNum} Safe Failure Handling Protocol (Lockfile & Resolution Errors)\n`;
  p += `If package manager resolution or lockfile regeneration fails:\n`;
  p += `1. **Preserve Original Evidence**: Do NOT delete existing lockfiles or discard git history.\n`;
  p += `2. **Report Failed Commands**: Record the exact command executed, exit status, and dependency conflict graph in the Phase E report.\n`;
  p += `3. **No Guessing**: Avoid replacing lockfiles with guessed or hand-written content.\n`;
  p += `4. **Honest Reporting**: Declare lockfile synchronization status as FAILED or UNSYNCHRONIZED; never claim success if the command errored.\n\n`;
  stepNum++;

  // 6. Verification Checklist & Regression Prevention
  p += `## 4. VERIFICATION CHECKLIST & REGRESSION PREVENTION\n`;
  p += `Complete all verification gates before reporting completion:\n`;
  p += `1. **Syntax Validation**: Manifest files (\`package.json\`, \`requirements.txt\`, \`go.mod\`) must parse cleanly without syntax errors.\n`;
  p += `2. **Dependency Resolution**: Run package manager installation commands. Confirm that resolution completes with 0 dependency conflicts.\n`;
  p += `3. **Backend Compilation & Syntax Gate**:\n`;
  p += `   - Python: Run \`python -m py_compile <modified_python_files>\` to guarantee zero syntax or indentation errors.\n`;
  p += `   - TypeScript / Node: Run \`npx tsc --noEmit\` or \`npm run build\` to confirm type safety and module resolution.\n`;
  p += `4. **Application Import & Boot Smoke-Test**:\n`;
  p += `   - Python: Run \`python -c "import <main_entrypoint>"\` (e.g. \`python -c "import main"\` or \`python -c "import app"\`) to confirm all backend modules load without \`ImportError\`, \`ModuleNotFoundError\`, or \`AttributeError\`.\n`;
  p += `   - Node.js: Run \`node -c <server_file>\` to verify syntax.\n`;
  p += `5. **Test Suite Execution**: Run project test suites (\`npm test\`, \`pytest\`, \`go test\`). Compare results against the Phase A baseline.\n`;
  p += `6. **CI/CD Action SHAs**: Verify that no unpinned mutable tags (\`@v...\` or \`@main\`) remain in \`.github/workflows/\`.\n`;
  p += `7. **Git Diff Hygiene**: Inspect \`git diff\` to confirm changes are strictly limited to Category A and justified Category B files.\n\n`;

  // 7. Acceptance Criteria
  p += `## 5. ACCEPTANCE CRITERIA\n`;
  p += `- All verified CVE/GHSA advisories identified in this audit are remediated or explicitly cataloged.\n`;
  p += `- Manifests and lockfiles remain synchronized and reproducible.\n`;
  p += `- Existing public API contracts, routing, and business logic remain functional.\n`;
  p += `- Any unverified advisory or major version migration requirement is explicitly noted in the final report.\n\n`;

  // 8. Required Final Report Template (Phase E)
  p += `## 6. REQUIRED FINAL REMEDIATION REPORT TEMPLATE (PHASE E)\n`;
  p += `Provide your final response adhering to this format:\n\n`;
  p += `\`\`\`markdown\n`;
  p += `### SUPPLYGRAPH SECURITY REMEDIATION REPORT\n\n`;
  p += `- **Original Raw Finding Count**: ${totalRawFindings}\n`;
  p += `- **Final Raw Finding Count**: [Count after fix]\n`;
  p += `- **Findings Verified as Fixed**: [Count / List]\n`;
  p += `- **Findings Mitigated with Residual Risk**: [Count / List]\n`;
  p += `- **Findings Requiring Manual Review**: [Count / List]\n`;
  p += `- **Findings Not Applicable / False Positives (with evidence)**: [Count / List]\n`;
  p += `- **Major Version Upgrades Applied**: [List packages and migration steps taken]\n\n`;
  p += `#### Modified Files:\n`;
  p += `- **Category A (Remediation Manifests & Lockfiles)**: [e.g. package.json, requirements.txt, .github/workflows/...]\n`;
  p += `- **Category B (Compatibility Files & Call-Sites)**: [e.g. backend/app/utils.py - updated Image.Resampling.LANCZOS for Pillow 10+ compatibility]\n`;
  p += `- **Category C (Prohibited Files Touched)**: None (0 files touched)\n\n`;
  p += `#### Package Versions Changed:\n`;
  p += `- [List: package @ old_version -> new_version]\n\n`;
  p += `#### Lockfiles Updated:\n`;
  p += `- [List: package-lock.json, poetry.lock, etc. (Or FAILED / UNSYNCHRONIZED)]\n\n`;
  p += `#### Commands Actually Executed:\n`;
  p += `- [List exact commands executed in terminal and their status; NEVER claim a command succeeded unless executed]\n\n`;
  p += `#### Tests & Builds Completed:\n`;
  p += `- [List test suites and build commands executed, with passing/failing status]\n\n`;
  p += `#### Post-Remediation Rescan Results:\n`;
  p += `- [Re-scan comparison: original findings vs remaining findings]\n\n`;
  p += `#### Remaining Limitations & Residual Risks:\n`;
  p += `- [Detail any unpatched advisories, missing test coverage, or environment constraints]\n`;
  p += `\`\`\`\n\n`;

  p += `Please begin with Phase A (Baseline Discovery) now.\n`;

  return p.trim();
}

/**
 * Generates an evidence-grounded prompt for an individual component or advisory.
 */
export function generateSingleAIFixPrompt(
  finding: any,
  relatedFindings?: any[],
  options: PromptGeneratorOptions = {}
): string {
  if (!finding) return "";
  const findingsList = relatedFindings && relatedFindings.length > 0 ? relatedFindings : [finding];
  const { pkgName, version: curVer, ecosystem, key } = getFindingPackage(finding);

  const candidateFixes: string[] = [];
  findingsList.forEach((f: any) => {
    if (f.recommendations) {
      f.recommendations.forEach((r: any) => {
        if (r?.fixed_version) candidateFixes.push(r.fixed_version);
      });
    }
    if (f.evidence) {
      f.evidence.forEach((e: any) => {
        if (e?.raw_data?.fixed_version) candidateFixes.push(e.raw_data.fixed_version);
        if (e?.raw_data?.fixed) candidateFixes.push(e.raw_data.fixed);
      });
    }
  });

  const resolution = resolveVersionWithConfidence(curVer, candidateFixes);
  const snippet = buildLockfileSnippet(finding, resolution.cleanVersion || undefined);

  let p = `# AI REMEDIATION TASK: Fix Security Vulnerabilities in \`${pkgName}\`\n\n`;
  p += `You are an expert Application Security Engineer and Software Developer.\n`;
  p += `SupplyGraph has identified security advisories affecting component \`${key}\` (${ecosystem.toUpperCase()}).\n`;
  p += `Remediate these vulnerabilities using minimal, evidence-grounded changes while preserving existing application functionality.\n\n`;

  p += `### COMPONENT AUDIT DETAILS:\n`;
  p += `- **Component Name**: \`${pkgName}\`\n`;
  p += `- **Installed Version**: \`${curVer || "unversioned / unknown"}\`\n`;
  p += `- **Ecosystem**: \`${ecosystem}\`\n`;
  p += `- **Highest Severity**: [${finding.severity || "MEDIUM"}]\n`;
  p += `- **Recommended Target Version**: \`${resolution.cleanVersion || "Manual Investigation Required"}\`\n`;
  p += `- **Recommendation State**: \`${resolution.category}\`\n`;
  p += `- **Remediation Note**: ${resolution.explanation}\n`;
  p += `- **Total Raw Findings for Component**: ${findingsList.length}\n\n`;

  p += `### ADVISORIES ADDRESSED:\n`;
  findingsList.slice(0, 10).forEach((f: any) => {
    p += `- **[${f.severity || "MEDIUM"}] ${f.title}**: ${f.description?.slice(0, 150) || ""}\n`;
  });
  if (findingsList.length > 10) {
    p += `- ... and ${findingsList.length - 10} additional security advisory signals\n`;
  }
  p += `\n`;

  if (snippet) {
    p += `### MANIFEST SPECIFICATION:\n`;
    if (ecosystem === "npm") {
      p += `Update \`package.json\` (check whether \`${pkgName}\` is direct or transitive):\n`;
    } else if (ecosystem === "pypi") {
      p += `Update \`requirements.txt\` or \`pyproject.toml\`:\n`;
    } else if (ecosystem === "golang") {
      p += `Update \`go.mod\`:\n`;
    } else {
      p += `Apply specification to dependency manifest:\n`;
    }
    p += `\`\`\`\n${snippet}\n\`\`\`\n\n`;
  }

  p += `### EXECUTION INSTRUCTIONS FOR AI:\n`;
  p += `1. **Scope Boundary**: Follow the 3-Tier Modification Scope Policy (Category A: manifest/lockfile, Category B: call-sites if API changed, Category C: prohibited).\n`;
  if (ecosystem === "npm") {
    p += `2. If direct: update version constraint to \`^${resolution.cleanVersion}\` in \`package.json\`.\n`;
    p += `3. If transitive: add to \`"overrides"\` (npm) or \`"resolutions"\` (yarn/pnpm) to avoid polluting direct dependencies.\n`;
    p += `4. Run targeted lockfile update: \`npm install ${pkgName}@${resolution.cleanVersion} --package-lock-only\`.\n`;
  } else if (ecosystem === "pypi") {
    p += `2. Update or pin \`${pkgName}${resolution.pep440Constraint || `>=${resolution.cleanVersion}`}\` in \`requirements.txt\` or \`pyproject.toml\`.\n`;
    p += `3. Run \`pip install -r requirements.txt\` (or targeted \`pip install "${pkgName}>=${resolution.cleanVersion}"\`).\n`;
  } else if (ecosystem === "golang") {
    p += `2. Run \`go get ${pkgName}@${resolution.cleanVersion.startsWith("v") ? resolution.cleanVersion : `v${resolution.cleanVersion}`}\`.\n`;
    p += `3. Run \`go mod tidy\` to synchronize \`go.sum\`.\n`;
  } else {
    p += `2. Update the dependency manifest with safe minimum version.\n`;
  }

  p += `5. **Category B Call-Site Compatibility Audit**: Search the codebase for occurrences of \`import ${pkgName}\` or \`require('${pkgName}')\`. If breaking changes exist, update call-sites and document changes.\n`;
  p += `6. Run project tests and backend smoke-tests to confirm application functions cleanly without regressions.\n`;
  p += `7. Present the updated file diff and verification test results.\n`;

  return p.trim();
}
