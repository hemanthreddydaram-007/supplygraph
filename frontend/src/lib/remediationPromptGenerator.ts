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
 * without making mathematically false guarantees of "zero regressions".
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

export type DependencyScope = "DIRECT" | "TRANSITIVE" | "DIRECT_AND_TRANSITIVE" | "UNKNOWN";

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
}

export interface AdvisoryDetail {
  id: string;
  title: string;
  severity: string;
  description?: string;
  fixedVersion?: string;
  affectedRange?: string;
}

export interface ComponentRemediationPackage {
  key: string;
  pkgName: string;
  installedVersion: string;
  ecosystem: SupportedEcosystem;
  scope: DependencyScope;
  declaredIn?: string;
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

/**
 * Resolves the optimal safe version from candidate fixes, returning explicit states:
 * - VERIFIED_FIXED_VERSION: Confirmed non-breaking patch release in same major version.
 * - VERIFIED_MINIMUM_FIXED_VERSION: Minimum confirmed fix (when unversioned or lowest safe floor).
 * - COMPATIBILITY_REVIEW_REQUIRED: Major-version upgrade crossing major boundary (migration assessment).
 * - NO_VERIFIED_FIX: Unpatched, disputed, or zero-day advisory.
 * - MANUAL_INVESTIGATION_REQUIRED: Non-standard version or malformed candidate tags.
 */
export function resolveVersionWithConfidence(
  installedVer: string | null | undefined,
  candidateFixes: (string | null | undefined)[]
): VersionResolution {
  const cleanCandidates = Array.from(new Set(
    candidateFixes
      .map((c) => (typeof c === "string" ? c.trim() : String(c || "").trim()))
      .filter((c) => Boolean(c) && c.toLowerCase() !== "latest" && !c.includes("patched_version"))
  ));

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

  // 1. Same major upgrades: same major and >= installedVer
  const sameMajor = parsedCandidates.filter((c) =>
    c.parsed.major === instParsed.major && compareSemVer(c.raw, installedVer) >= 0
  );

  if (sameMajor.length > 0) {
    // Pick highest patch in same major to resolve all advisories in that major branch
    sameMajor.sort((a, b) => compareSemVer(b.raw, a.raw));
    const best = sameMajor[0].raw;
    return {
      rawFixed: best,
      cleanVersion: best,
      category: "VERIFIED_FIXED_VERSION",
      isMajorUpgrade: false,
      majorDiff: 0,
      explanation: `Verified patch release within major version ${instParsed.major} (resolves all known advisories with minimized breaking change risk).`,
      pep440Constraint: `>=${best}`,
      npmConstraint: `^${best}`,
    };
  }

  // 2. Higher major upgrades: major > installedVer
  const higherMajor = parsedCandidates.filter((c) => c.parsed.major > instParsed.major);
  if (higherMajor.length > 0) {
    higherMajor.sort((a, b) => compareSemVer(a.raw, b.raw));
    const lowestHigherMajor = higherMajor[0].parsed.major;
    const inLowestHigher = higherMajor.filter((c) => c.parsed.major === lowestHigherMajor);
    inLowestHigher.sort((a, b) => compareSemVer(b.raw, a.raw));
    const best = inLowestHigher[0].raw;
    const diff = lowestHigherMajor - instParsed.major;
    return {
      rawFixed: best,
      cleanVersion: best,
      category: "COMPATIBILITY_REVIEW_REQUIRED",
      isMajorUpgrade: true,
      majorDiff: diff,
      explanation: `⚠️ Major version upgrade required (${instParsed.major}.x -> ${lowestHigherMajor}.x). Potential breaking API changes require migration assessment.`,
      pep440Constraint: `>=${best}`,
      npmConstraint: `^${best}`,
    };
  }

  // 3. Only backports to older releases exist
  return {
    rawFixed: "",
    cleanVersion: "",
    category: "NO_VERIFIED_FIX",
    isMajorUpgrade: false,
    majorDiff: 0,
    explanation: "Available advisory fixes apply only to older release branches. Upstream has not published a fix for this branch.",
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
 * Inspects scan data to detect package managers, lockfiles, and workspace layouts.
 */
export function detectPackageManagers(scanData: any): PackageManagerDetectionResult {
  const lockTypes: string[] = scanData?.scan?.lockfile_types || [];
  const files: { path: string }[] = scanData?.files || [];
  const filePaths = new Set([...lockTypes, ...files.map(f => f.path)]);

  let nodePm: "npm" | "pnpm" | "yarn" | "bun" = "npm";
  if (Array.from(filePaths).some(p => p.includes("pnpm-lock.yaml"))) nodePm = "pnpm";
  else if (Array.from(filePaths).some(p => p.includes("yarn.lock"))) nodePm = "yarn";
  else if (Array.from(filePaths).some(p => p.includes("bun.lockb"))) nodePm = "bun";

  let pythonPm: "pip" | "poetry" | "pipenv" | "uv" = "pip";
  if (Array.from(filePaths).some(p => p.includes("poetry.lock"))) pythonPm = "poetry";
  else if (Array.from(filePaths).some(p => p.includes("Pipfile.lock") || p.includes("Pipfile"))) pythonPm = "pipenv";
  else if (Array.from(filePaths).some(p => p.includes("uv.lock"))) pythonPm = "uv";

  const hasGo = Array.from(filePaths).some(p => p.includes("go.mod") || p.includes("go.sum"));
  const hasCargo = Array.from(filePaths).some(p => p.includes("Cargo.toml") || p.includes("Cargo.lock"));

  // Detect workspace configurations and multiple manifests
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
    workspaces: {
      manifests: nodeManifests,
      isWorkspace,
      packageManager: nodePm,
    },
  };
}

/**
 * Builds lockfile configuration snippets (used in finding cards, modals, and prompt blocks).
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
    return `# .github/workflows/*.yml - Enforce least-privilege permissions\npermissions:\n  contents: read\n  pull-requests: write\n# Pin actions to full 40-character commit SHA with version comment:\n# uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2`;
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

  // Build component metadata index for direct vs transitive lookup
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
        // Resolve scope and declared_in from SBOM component metadata
        const comp = compIndex[pkgName.toLowerCase()] || compIndex[f.origin_candidate?.toLowerCase()] || null;
        let scope: DependencyScope = "UNKNOWN";
        if (comp) {
          if (comp.is_direct && comp.is_transitive) scope = "DIRECT_AND_TRANSITIVE";
          else if (comp.is_direct) scope = "DIRECT";
          else if (comp.is_transitive) scope = "TRANSITIVE";
        }

        packageMap[key] = {
          key,
          pkgName,
          installedVersion: version,
          ecosystem,
          scope,
          declaredIn: comp?.declared_in,
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

      // Track dependency path if present in evidence or origin
      if (f.origin_candidate && !packageMap[key].dependencyPaths?.includes(f.origin_candidate)) {
        packageMap[key].dependencyPaths?.push(f.origin_candidate);
      }

      const currentSev = f.severity?.toUpperCase() || "LOW";
      const sevOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
      const groupSevIdx = sevOrder.indexOf(packageMap[key].highestSeverity);
      const curSevIdx = sevOrder.indexOf(currentSev);
      if (curSevIdx !== -1 && (groupSevIdx === -1 || curSevIdx < groupSevIdx)) {
        packageMap[key].highestSeverity = currentSev;
      }

      // Extract unique advisory IDs (GHSA, CVE, GO, PYSEC)
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

  // Calculate authoritative resolution for each component
  return Object.values(packageMap).map((pkg) => {
    const candidateFixes: string[] = [];
    pkg.findings.forEach((f) => {
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

    const resolution = resolveVersionWithConfidence(pkg.installedVersion, candidateFixes);
    return {
      ...pkg,
      resolution,
    };
  });
}

/**
 * Generates an evidence-grounded Master AI Fix Prompt conforming to the 5-phase protocol and honest reporting.
 */
export function generateMasterAIFixPrompt(scanData: any, options: PromptGeneratorOptions = {}): string {
  if (!scanData) return "";
  const repo = scanData?.scan?.repository_url || "Target Repository / Local Project";
  const findings = scanData?.findings || [];
  const codeReviews = scanData?.code_reviews || [];
  const blastRadius = scanData?.scan?.blast_radius_score || 0;
  const packagesList = aggregateComponentPackages(scanData);

  const { nodePm, pythonPm, hasGo, hasCargo, workspaces, manifestPaths } = detectPackageManagers(scanData);

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

  // Separate backend source code reviews from CI/CD workflow reviews
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

  // 2. Strict Execution Rules Without False Guarantees
  p += `### STRICT EXECUTION RULES FOR AI ASSISTANTS (Antigravity / Cursor / Claude / ChatGPT / Copilot):\n`;
  p += `1. **Preserve Application Functionality**: Maintain existing features, public API contracts, database schemas, business logic, routing, and authentication controls.\n`;
  p += `2. **Honest Engineering Boundaries**:\n`;
  p += `   - Do NOT promise "zero regressions", "100% backward compatibility", "100% vulnerability elimination", or "guaranteed one-shot execution". These are desired objectives, not guaranteed facts.\n`;
  p += `   - If a major upgrade is necessary, perform compatibility analysis, review upstream migration notes, and execute additional verification tests.\n`;
  p += `   - If test suites are missing or cannot run in the execution environment, clearly report the resulting uncertainty in the final report.\n`;
  p += `   - If the task exceeds the available execution budget, apply changes in controlled batches and reconcile every original finding before declaring completion.\n`;
  p += `3. **No Fabricated Evidence**: Never invent package versions, advisory IDs, commit SHAs, or upstream fix claims.\n`;
  p += `4. **Targeted Precision**: Modify ONLY the specified files. Avoid unrelated refactoring or formatting churn.\n\n`;

  // 3. Repository Context & Evidence Metadata
  p += `## 1. REPOSITORY CONTEXT & AUDIT INVENTORY METADATA\n`;
  p += `- **Target Project / Repository**: \`${repo}\`\n`;
  if (options.targetBranch) p += `- **Target Branch**: \`${options.targetBranch}\`\n`;
  p += `- **Total Raw Security Findings Reported**: ${totalRawFindings}\n`;
  p += `- **Unique Security Advisories (CVE / GHSA / OSV)**: ${totalUniqueAdvisories}\n`;
  p += `- **Unique Affected Packages / Components**: ${totalAffectedComponents}\n`;
  p += `- **Affected Dependency Paths / Manifest Locations**: ${totalAffectedPaths}\n`;
  p += `- **CI/CD Pipeline Security Findings**: ${codeReviews.length + cicdFindings.length}\n`;
  p += `- **Supply Chain Blast Radius Score**: ${blastRadius}/100\n`;
  p += `- **Authoritative Intelligence Sources**: OSV.dev (Open Source Vulnerabilities), GitHub Advisory Database (GHSA), NVD/CVE, static AST analysis, OpenSSF workflow audit.\n\n`;

  p += `> ⚠️ **INVENTORY COUNTING RULE**: Raw finding counts, unique advisories, affected packages, and dependency paths are distinct metrics and must NOT be treated as interchangeable. An audit reporting ${totalRawFindings} raw findings may represent ${totalUniqueAdvisories} unique advisories across ${totalAffectedComponents} packages. Every raw finding must be tracked and reconciled in Phase E.\n\n`;

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
  p += `2. **Preserve Contracts**: Do NOT modify unrelated features, business logic, public API contracts, database schemas, or authentication/authorization rules.\n`;
  p += `3. **Lockfile Synchronization**: Update manifests and regenerate lockfiles synchronously using the detected package manager.\n`;
  p += `4. **No Suppressions**: Do NOT delete tests, weaken assertion thresholds, or suppress linting/security errors to achieve a passing status.\n\n`;

  p += `### PHASE D — VERIFY\n`;
  p += `1. **Manifest & Lockfile Integrity**: Validate that manifests are syntactically valid and lockfiles resolve cleanly.\n`;
  p += `2. **Run Full Test Suite**: Execute project test suites and verify that no functional regressions or broken behavior were introduced compared to Phase A baseline.\n`;
  p += `3. **Production Build & Lint**: Run build commands (\`npm run build\`, etc.) to confirm packaging and compilation succeed.\n`;
  p += `4. **API Contract & Workflow Tests**: Test affected endpoints and workflows.\n`;
  p += `5. **Post-Remediation Rescan**: Re-run vulnerability scanning or review dependency tree to verify advisories are closed.\n`;
  p += `6. **Diff Audit**: Review \`git diff\` to ensure no unintended formatting churn or extraneous files were touched.\n\n`;

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
    const transitivePackages = npmPackages.filter(pkg => pkg.scope === "TRANSITIVE" || pkg.scope === "DIRECT_AND_TRANSITIVE");

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
      p += `  - **Target Version**: \`${pkg.resolution.cleanVersion || "Manual Investigation Required"}\`\n`;
      p += `  - **Remediation Note**: ${pkg.resolution.explanation}\n`;
      p += `  - **Advisories Addressed**: ${pkg.advisories.map(a => a.id).slice(0, 8).join(", ")}${pkg.advisories.length > 8 ? ` +${pkg.advisories.length - 8} more` : ""}\n`;
      if (pkg.resolution.category === "COMPATIBILITY_REVIEW_REQUIRED") {
        p += `  - **Compatibility Assessment**: Major version bump (${pkg.installedVersion} -> ${pkg.resolution.cleanVersion}). Audit package changelog for breaking changes before committing.\n`;
      }
    });

    p += `\n> **Lockfile Synchronization Command**:\n`;
    p += `\`\`\`bash\n`;
    if (nodePm === "pnpm") p += `pnpm install\n`;
    else if (nodePm === "yarn") p += `yarn install\n`;
    else if (nodePm === "bun") p += `bun install\n`;
    else p += `npm install\n`;
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
      p += `  - **Target Version**: \`${pkg.resolution.pep440Constraint || "Manual Investigation Required"}\`\n`;
      p += `  - **Remediation Note**: ${pkg.resolution.explanation}\n`;
      p += `  - **Advisories Addressed**: ${pkg.advisories.map(a => a.id).slice(0, 8).join(", ")}${pkg.advisories.length > 8 ? ` +${pkg.advisories.length - 8} more` : ""}\n`;
      if (pkg.resolution.category === "COMPATIBILITY_REVIEW_REQUIRED" || pkg.resolution.isMajorUpgrade) {
        p += `  - **Compatibility Assessment**: Major version bump (${pkg.installedVersion} -> ${pkg.resolution.cleanVersion}). Audit package changelog for breaking changes before committing.\n`;
      }
    });

    p += `\n> **Lockfile / Environment Synchronization Command**:\n`;
    p += `> **Note**: Never assume that \`pip install\` automatically regenerates a lockfile. For Poetry, Pipenv, or uv, run the dedicated lock command:\n`;
    p += `\`\`\`bash\n`;
    if (pythonPm === "poetry") p += `poetry lock --no-update && poetry install\n`;
    else if (pythonPm === "pipenv") p += `pipenv lock && pipenv install\n`;
    else if (pythonPm === "uv") p += `uv lock && uv sync\n`;
    else p += `pip install -r requirements.txt --upgrade\n`;
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
    p += `Update lockfile with: \`cargo update\`\n\n`;
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
    // Section 6 requirement: state scope of performed checks rather than blanket claims
    p += `**Scope of performed CI/CD checks**:\n`;
    p += `1. Immutable commit SHA pinning for third-party actions (\`uses:\` directives).\n`;
    p += `2. Least-privilege permissions analysis (checks for blanket \`write-all\` permissions).\n`;
    p += `3. Script injection vulnerability detection in \`run:\` steps (untrusted \`github.event\` context variables).\n`;
    p += `4. Insecure download-and-execute patterns (\`curl | bash\`).\n\n`;
    p += `- **Result**: 0 actionable risks detected across audited workflow files.\n`;
    p += `- **Note**: This audit evaluates static workflow configurations. Self-hosted runner isolation, repository secret handling, and upstream action implementation integrity require separate operational assessment.\n\n`;
  }
  stepNum++;

  // Call-Site Dependency Compatibility & Refactoring Audit
  p += `### 3.${stepNum} Call-Site Dependency Audit & API Compatibility Refactoring\n`;
  p += `> ⚠️ **WHY BACKENDS BREAK ON DEPENDENCY UPDATES**:\n`;
  p += `> Bumping package versions in manifests (\`package.json\`, \`requirements.txt\`, \`go.mod\`) changes the installed library, but **DOES NOT update the application code calling it**. If the new version deprecates or removes an API, the backend will crash at startup with \`ImportError\`, \`AttributeError\`, or \`TypeError\`.\n`;
  p += `>\n`;
  p += `> **MANDATORY CALL-SITE AUDIT INSTRUCTIONS FOR AI**:\n`;
  p += `> You MUST search every source file in the project for calls to the upgraded dependencies:\n`;
  p += `> 1. **Scan Imports in Project Code**:\n`;
  p += `>    - Python: Run \`grep -rn "import <package>" .\` and \`grep -rn "from <package>" .\`\n`;
  p += `>    - Node.js: Run \`grep -rn "require('<package>')" .\` and \`grep -rn "from '<package>'" .\`\n`;
  p += `> 2. **Check for Common High-Risk Breaking Change Signatures**:\n`;
  p += `>    - **Pillow (v10+ / v13+)**: \`Image.ANTIALIAS\` was removed. Replace with \`Image.Resampling.LANCZOS\`.\n`;
  p += `>    - **Pydantic (v1 -> v2)**: \`from pydantic import BaseSettings\` raises \`ImportError\`. Use \`from pydantic_settings import BaseSettings\`. Replace \`.dict()\` with \`.model_dump()\`. Replace \`@validator\` with \`@field_validator\`.\n`;
  p += `>    - **SQLAlchemy (v1.4 -> v2.0)**: Raw SQL strings in \`session.execute()\` must be wrapped with \`text("...")\` from \`sqlalchemy import text\`.\n`;
  p += `>    - **Requests & Urllib3**: Ensure \`verify=False\` is removed, and custom adapter connection pools match current syntax.\n`;
  p += `>    - **Next.js (v14 -> v15/v16)**: \`params\` and \`searchParams\` in Route Handlers and Pages must be awaited (\`const { id } = await params\`).\n`;
  p += `>    - **PyJWT / JSONWebToken**: Explicitly declare verification algorithms: \`jwt.decode(token, secret, algorithms=["HS256"])\`.\n`;
  p += `> 3. **Refactor Call-Sites Immediately**: Update all backend files referencing these packages to ensure zero runtime \`ImportError\` or \`AttributeError\` exceptions when the backend server boots.\n\n`;
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
  p += `7. **Git Diff Hygiene**: Inspect \`git diff\` to confirm changes are strictly limited to the security issues identified above.\n\n`;

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
  p += `- [List all files changed, e.g. package.json, requirements.txt, .github/workflows/...]\n\n`;
  p += `#### Package Versions Changed:\n`;
  p += `- [List: package @ old_version -> new_version]\n\n`;
  p += `#### Lockfiles Updated:\n`;
  p += `- [List: package-lock.json, poetry.lock, etc.]\n\n`;
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
  if (ecosystem === "npm") {
    p += `1. Locate where \`${pkgName}\` is declared in \`package.json\`.\n`;
    p += `2. If direct: update version constraint to \`^${resolution.cleanVersion}\`.\n`;
    p += `3. If transitive: add to \`"overrides"\` (npm) or \`"resolutions"\` (yarn/pnpm) to avoid polluting direct dependencies.\n`;
    p += `4. Run \`npm install\` (or \`pnpm install\` / \`yarn install\`) to synchronize lockfile.\n`;
  } else if (ecosystem === "pypi") {
    p += `1. Locate \`requirements.txt\` or \`pyproject.toml\`.\n`;
    p += `2. Update or pin \`${pkgName}${resolution.pep440Constraint || `>=${resolution.cleanVersion}`}\`.\n`;
    p += `3. Run \`pip install -r requirements.txt --upgrade\` (or \`poetry update\` / \`uv sync\`).\n`;
  } else if (ecosystem === "golang") {
    p += `1. Run \`go get ${pkgName}@${resolution.cleanVersion.startsWith("v") ? resolution.cleanVersion : `v${resolution.cleanVersion}`}\`.\n`;
    p += `2. Run \`go mod tidy\` to synchronize \`go.sum\`.\n`;
  } else {
    p += `1. Update the dependency manifest with safe minimum version.\n`;
  }

  p += `5. **Call-Site Compatibility Audit**: Search the codebase for all occurrences of \`import ${pkgName}\` or \`require('${pkgName}')\`. Verify that no deprecated methods or altered function signatures are called.\n`;
  p += `6. Run project tests and backend smoke-tests to confirm application functions cleanly without regressions.\n`;
  p += `7. Present the updated file diff and verification test results.\n`;

  return p.trim();
}
