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
}

export interface PromptGeneratorOptions {
  batchSize?: number;
  targetBranch?: string;
  includeAstRefactoring?: boolean;
  includeCicdHardening?: boolean;
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
 * Resolves the optimal safe version from candidate fixes, distinguishing:
 * - VERIFIED_SAME_MAJOR: Non-breaking security patch in same major.
 * - VERIFIED_MAJOR_UPGRADE: Breaking major upgrade (migration required).
 * - INVESTIGATION_REQUIRED: No verified upstream release.
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
      category: "INVESTIGATION_REQUIRED",
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
        category: "MINIMUM_KNOWN_FIXED",
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
      category: "INVESTIGATION_REQUIRED",
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
      category: "INVESTIGATION_REQUIRED",
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
      category: "VERIFIED_SAME_MAJOR",
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
      category: "VERIFIED_MAJOR_UPGRADE",
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
    category: "INVESTIGATION_REQUIRED",
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
 * Inspects scan data to detect package managers and repository layout.
 */
export function detectPackageManagers(scanData: any): {
  nodePm: "npm" | "pnpm" | "yarn" | "bun";
  pythonPm: "pip" | "poetry" | "pipenv" | "uv";
  hasGo: boolean;
  hasCargo: boolean;
} {
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

  return { nodePm, pythonPm, hasGo, hasCargo };
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
          resolution: {
            rawFixed: "",
            cleanVersion: "",
            category: "INVESTIGATION_REQUIRED",
            isMajorUpgrade: false,
            majorDiff: 0,
            explanation: "",
          },
        };
      }

      packageMap[key].findings.push(f);

      const currentSev = f.severity?.toUpperCase() || "LOW";
      const sevOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
      const groupSevIdx = sevOrder.indexOf(packageMap[key].highestSeverity);
      const curSevIdx = sevOrder.indexOf(currentSev);
      if (curSevIdx !== -1 && (groupSevIdx === -1 || curSevIdx < groupSevIdx)) {
        packageMap[key].highestSeverity = currentSev;
      }

      // Extract unique advisory IDs
      const cveMatch = f.title?.match(/(GHSA-[a-z0-9-]+|CVE-\d{4}-\d+|GO-\d{4}-\d+|PYSEC-\d{4}-\d+)/i);
      const advId = cveMatch ? cveMatch[1] : (f.id || `FINDING-${packageMap[key].advisories.length + 1}`);
      if (!packageMap[key].advisories.some(a => a.id === advId)) {
        let advFix = "";
        if (f.recommendations?.[0]?.fixed_version) advFix = f.recommendations[0].fixed_version;
        else if (f.evidence) {
          for (const ev of f.evidence) {
            if (ev?.raw_data?.fixed_version) { advFix = ev.raw_data.fixed_version; break; }
            if (ev?.raw_data?.fixed) { advFix = ev.raw_data.fixed; break; }
          }
        }
        packageMap[key].advisories.push({
          id: advId,
          title: f.title || "Vulnerability Advisory",
          severity: f.severity || "MEDIUM",
          description: f.description,
          fixedVersion: advFix,
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
 * Generates an evidence-grounded Master AI Fix Prompt conforming to Section 9 structure.
 */
export function generateMasterAIFixPrompt(scanData: any, options: PromptGeneratorOptions = {}): string {
  if (!scanData) return "";
  const repo = scanData?.scan?.repository_url || "Target Repository / Local Project";
  const findings = scanData?.findings || [];
  const codeReviews = scanData?.code_reviews || [];
  const blastRadius = scanData?.scan?.blast_radius_score || 0;
  const packagesList = aggregateComponentPackages(scanData);

  const { nodePm, pythonPm, hasGo, hasCargo } = detectPackageManagers(scanData);

  const npmPackages = packagesList.filter((p) => p.ecosystem === "npm");
  const pypiPackages = packagesList.filter((p) => p.ecosystem === "pypi");
  const goPackages = packagesList.filter((p) => p.ecosystem === "golang");
  const cargoPackages = packagesList.filter((p) => p.ecosystem === "cargo");
  const cicdFindings = findings.filter((f: any) => f.finding_type === "CICD_RISK" || f.title?.includes("CI/CD"));
  const astFindings = findings.filter((f: any) => f.finding_type === "AST" || f.title?.includes("AST") || f.finding_type === "SUSPICIOUS");

  let p = "";

  // 1. Role and Objective
  p += `# AI SECURITY REMEDIATION TASK: Complete Codebase Vulnerability Remediation\n\n`;
  p += `You are an expert Principal Application Security Engineer, Software Supply-Chain Specialist, and Senior Full-Stack Architect.\n`;
  p += `SupplyGraph has conducted an evidence-bounded supply-chain security audit on this project and identified security vulnerabilities, outdated dependencies, and CI/CD supply-chain risks.\n`;
  p += `Your objective is to remediate confirmed security vulnerabilities using minimal, targeted, evidence-grounded modifications while preserving existing application functionality and minimizing regressions.\n\n`;

  // 2. Repository Context & Evidence Metadata
  p += `## 1. REPOSITORY CONTEXT & AUDIT METADATA\n`;
  p += `- **Target Project / Repository**: \`${repo}\`\n`;
  if (options.targetBranch) p += `- **Target Branch**: \`${options.targetBranch}\`\n`;
  p += `- **Total Raw Findings Detected**: ${findings.length}\n`;
  p += `- **Unique Vulnerable Components**: ${packagesList.length}\n`;
  p += `- **CI/CD Pipeline Security Findings**: ${codeReviews.length + cicdFindings.length}\n`;
  p += `- **Supply Chain Blast Radius Score**: ${blastRadius}/100\n`;
  p += `- **Authoritative Intelligence Sources**: OSV.dev (Open Source Vulnerabilities), GitHub Advisory Database (GHSA), NVD/CVE, static AST analysis, OpenSSF workflow audit.\n\n`;

  // 3. Staged 5-Phase Remediation Protocol
  p += `## 2. STAGED REMEDIATION PROTOCOL (STRICT EXECUTION SEQUENCE)\n`;
  p += `You MUST follow this 5-phase engineering protocol to ensure systematic verification and prevent broken builds:\n\n`;

  p += `### PHASE A — ESTABLISH BASELINE\n`;
  p += `1. **Git State Inspection**: Check \`git status\` and preserve any uncommitted user work.\n`;
  p += `2. **Environment & Tool Discovery**: Detect active package manager (\`${nodePm}\`, \`${pythonPm}\`, \`go\`, \`cargo\`), Node.js/Python runtimes, and workspace configuration.\n`;
  p += `3. **Baseline Test Execution**: Run existing test suites (\`npm test\`, \`pytest\`, \`go test\`) and record initial passing/failing status before editing any file.\n\n`;

  p += `### PHASE B — PLAN REMEDIATION\n`;
  p += `1. **Inventory Mapping**: Review Section 3 below. Map every finding to its exact manifest (\`package.json\`, \`requirements.txt\`, \`go.mod\`) or workflow file.\n`;
  p += `2. **Scope Distinction**: Distinguish direct dependencies from transitive sub-dependencies. Do NOT add transitive packages into direct manifest dependencies unless justified.\n`;
  p += `3. **Breaking Change Assessment**: Review all packages flagged with \`[MAJOR UPGRADE REQUIRED]\` and check migration notes before applying.\n`;
  p += `4. **Batch Execution Plan**: If modifying more than 15 packages, apply changes in staged batches.\n\n`;

  p += `### PHASE C — IMPLEMENT CHANGES\n`;
  p += `1. **Surgical Modifications**: Apply the smallest suitable version bump or code patch that eliminates the vulnerability.\n`;
  p += `2. **Preserve Contracts**: Do NOT modify unrelated features, business logic, public API contracts, database schemas, or authentication/authorization rules.\n`;
  p += `3. **Lockfile Synchronization**: Update manifests and regenerate lockfiles synchronously using the detected package manager.\n`;
  p += `4. **No Suppressions**: Do NOT delete tests, weaken assertion thresholds, or suppress linting/security errors to achieve a passing status.\n\n`;

  p += `### PHASE D — VERIFY\n`;
  p += `1. **Manifest & Lockfile Integrity**: Validate that manifests are syntactically valid and lockfiles resolve cleanly.\n`;
  p += `2. **Run Full Test Suite**: Execute project test suites and verify that zero functional regressions were introduced compared to Phase A baseline.\n`;
  p += `3. **Production Build & Lint**: Run build commands (\`npm run build\`, etc.) to confirm packaging and compilation succeed.\n`;
  p += `4. **Post-Remediation Rescan**: Re-run vulnerability scanning or review dependency tree to verify advisories are closed.\n`;
  p += `5. **Diff Audit**: Review \`git diff\` to ensure no unintended formatting churn or extraneous files were touched.\n\n`;

  p += `### PHASE E — REPORT\n`;
  p += `Produce a structured final reconciliation report adhering to the template in Section 7.\n\n`;

  p += `============================================================\n\n`;

  // 4. Finding-by-Finding Remediation Inventory
  p += `## 3. EVIDENCE-BASED REMEDIATION INSTRUCTIONS\n\n`;

  let stepNum = 1;

  // Node.js / npm Section
  if (npmPackages.length > 0) {
    p += `### 3.${stepNum} JavaScript / Node.js Dependencies (\`package.json\`)\n`;
    p += `- **Detected Package Manager**: \`${nodePm}\`\n`;
    p += `- **Target File(s)**: Locate \`package.json\` in project root or workspace directories (e.g., \`frontend/package.json\`).\n\n`;

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
      const upgradeTag = pkg.resolution.isMajorUpgrade ? " ⚠️ [MAJOR UPGRADE REQUIRED]" : "";
      p += `- **\`${pkg.pkgName}@${pkg.installedVersion || "installed"}\`** [${pkg.highestSeverity}] (${pkg.findings.length} advisory finding(s))${upgradeTag}\n`;
      p += `  - **Category**: ${pkg.resolution.category}\n`;
      p += `  - **Scope**: ${pkg.scope} dependency${pkg.declaredIn ? ` (declared in \`${pkg.declaredIn}\`)` : ""}\n`;
      p += `  - **Recommended Safe Version**: \`${pkg.resolution.cleanVersion || "Manual Investigation"}\`\n`;
      p += `  - **Remediation Note**: ${pkg.resolution.explanation}\n`;
      p += `  - **Advisories Addressed**: ${pkg.advisories.map(a => a.id).slice(0, 8).join(", ")}${pkg.advisories.length > 8 ? ` +${pkg.advisories.length - 8} more` : ""}\n`;
      if (pkg.resolution.isMajorUpgrade) {
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

    const verifiedPypi = pypiPackages.filter(p => p.resolution.category !== "INVESTIGATION_REQUIRED");
    const unverifiedPypi = pypiPackages.filter(p => p.resolution.category === "INVESTIGATION_REQUIRED");

    if (verifiedPypi.length > 0) {
      p += `#### A. PEP 440 Pinning Constraints:\n`;
      p += `\`\`\`text\n`;
      verifiedPypi.forEach((pkg) => {
        p += `${pkg.pkgName}${pkg.resolution.pep440Constraint}  # Pinned by SupplyGraph (${pkg.findings.length} advisory finding(s))\n`;
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
      const upgradeTag = pkg.resolution.isMajorUpgrade ? " ⚠️ [MAJOR UPGRADE REQUIRED]" : "";
      p += `- **\`${pkg.pkgName}@${pkg.installedVersion || "installed"}\`** [${pkg.highestSeverity}] (${pkg.findings.length} advisory finding(s))${upgradeTag}\n`;
      p += `  - **Category**: ${pkg.resolution.category}\n`;
      p += `  - **Scope**: ${pkg.scope} dependency${pkg.declaredIn ? ` (declared in \`${pkg.declaredIn}\`)` : ""}\n`;
      p += `  - **Recommended Target**: \`${pkg.resolution.pep440Constraint || "Manual Investigation"}\`\n`;
      p += `  - **Remediation Note**: ${pkg.resolution.explanation}\n`;
      p += `  - **Advisories Addressed**: ${pkg.advisories.map(a => a.id).slice(0, 8).join(", ")}${pkg.advisories.length > 8 ? ` +${pkg.advisories.length - 8} more` : ""}\n`;
    });

    p += `\n> **Lockfile / Environment Synchronization Command**:\n`;
    p += `\`\`\`bash\n`;
    if (pythonPm === "poetry") p += `poetry update\n`;
    else if (pythonPm === "pipenv") p += `pipenv update\n`;
    else if (pythonPm === "uv") p += `uv sync\n`;
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

  // CI/CD Workflows Section
  p += `### 3.${stepNum} CI/CD Pipeline Security Hardening (\`.github/workflows/\`)\n`;
  if (codeReviews.length > 0) {
    codeReviews.forEach((cr: any, idx: number) => {
      p += `#### Patch #${idx + 1}: ${cr.title} [${cr.severity}]\n`;
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
    p += `All CI/CD workflows comply with OpenSSF immutable SHA-pinning and least-privilege standards.\n\n`;
  }
  stepNum++;

  // AST / Application Code Section
  if (astFindings.length > 0) {
    p += `### 3.${stepNum} Application Source Code Hardening (AST Findings)\n`;
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

  // 5. Verification Checklist & Regression Prevention
  p += `## 4. VERIFICATION CHECKLIST & REGRESSION PREVENTION\n`;
  p += `Complete all verification gates before reporting completion:\n`;
  p += `1. **Syntax Validation**: Manifest files (\`package.json\`, \`requirements.txt\`, \`go.mod\`) must parse cleanly without syntax errors.\n`;
  p += `2. **Dependency Resolution**: Run package manager installation commands. Confirm that resolution completes with 0 dependency conflicts.\n`;
  p += `3. **Test Suite Execution**: Run project test suites (\`npm test\`, \`pytest\`, \`go test\`). Compare results against the Phase A baseline.\n`;
  p += `4. **Build Verification**: Run production build (\`npm run build\`, etc.) to confirm bundling and static analysis pass.\n`;
  p += `5. **CI/CD Action SHAs**: Verify that no unpinned mutable tags (\`@v...\` or \`@main\`) remain in \`.github/workflows/\`.\n`;
  p += `6. **Git Diff Hygiene**: Inspect \`git diff\` to confirm changes are strictly limited to the security issues identified above.\n\n`;

  // 6. Acceptance Criteria
  p += `## 5. ACCEPTANCE CRITERIA\n`;
  p += `- All verified CVE/GHSA advisories identified in this audit are remediated or explicitly cataloged.\n`;
  p += `- Manifests and lockfiles remain synchronized and reproducible.\n`;
  p += `- Existing public API contracts, routing, and business logic remain functional.\n`;
  p += `- Any unverified advisory or major version migration requirement is explicitly noted in the final report.\n\n`;

  // 7. Required Final Report Template
  p += `## 6. REQUIRED FINAL REMEDIATION REPORT TEMPLATE\n`;
  p += `Provide your final response adhering to this format:\n\n`;
  p += `\`\`\`markdown\n`;
  p += `### SUPPLYGRAPH SECURITY REMEDIATION REPORT\n\n`;
  p += `- **Baseline Test Status**: [Passed / Failed / No Tests Found]\n`;
  p += `- **Total Raw Findings in Audit**: ${findings.length}\n`;
  p += `- **Findings Successfully Remediated**: [Count]\n`;
  p += `- **Findings Requiring Manual Investigation**: [Count]\n`;
  p += `- **Major Version Upgrades Applied**: [List packages and migration steps taken]\n\n`;
  p += `#### Modified Files:\n`;
  p += `- [List all files changed, e.g. package.json, requirements.txt, .github/workflows/...]\n\n`;
  p += `#### Verification Commands Executed:\n`;
  p += `- [List exact commands executed and their output summary]\n\n`;
  p += `#### Unresolved Risks & Limitations:\n`;
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
  p += `- **Recommended Safe Version**: \`${resolution.cleanVersion || "Manual Investigation"}\`\n`;
  p += `- **Confidence Category**: ${resolution.category}\n`;
  p += `- **Remediation Note**: ${resolution.explanation}\n`;
  p += `- **Total Related Findings**: ${findingsList.length}\n\n`;

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

  p += `5. Run project tests to confirm application functions cleanly.\n`;
  p += `6. Present the updated file diff and verification test results.\n`;

  return p.trim();
}
