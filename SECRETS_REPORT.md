# SupplyGraph — Secrets & Public-Repo Safety Report

**Scan Date:** October 19, 2026  
**Auditor:** Automated Credential Scanner & Security Reviewer  
**Scope:** Working tree files and all 22 Git commits in repository history.  

---

## 1. Executive Summary & Action Required

> [!WARNING]
> **ROTATE IMMEDIATELY**  
> Active personal access tokens (GitHub PATs) were detected in working tree files. Even though git history contains zero hardcoded production tokens, any token present on disk must be revoked and rotated immediately to eliminate risk.

---

## 2. Git History Audit (All 22 Commits)

- **Total Commits Analyzed:** 22
- **Hardcoded Secrets Committed to Git History:** **0 (ZERO)**
- **Verification Details:**
  - Scanned for: `ghp_`, `github_pat_`, `AKIA...`, `sk-...`, `AIza...`, 64-character hex private keys, and BIP-39 mnemonic seeds.
  - Historical matches in commit `d9d5fa6` were verified as safe documentation placeholders (`.env.example: GITHUB_TOKEN=ghp_your_token_here`, `docs/deployment.md: GITHUB_TOKEN=ghp_your_github_personal_access_token_here`).

---

## 3. Working Tree Findings (NEVER Showing Values)

| File Location | Secret Type Detected | Status & Action Taken |
|---|---|---|
| `check_repo.py:3` | GitHub Personal Access Token (`ghp_...`) | Untracked temporary script. Added to `.gitignore`. **ROTATE IMMEDIATELY in GitHub Settings**. |
| `check_repo2.py:3` | GitHub Personal Access Token (`ghp_...`) | Untracked temporary script. Added to `.gitignore`. **ROTATE IMMEDIATELY in GitHub Settings**. |
| `backend/.env:1` | GitHub Personal Access Token (`ghp_...`) | Local untracked environment file. Protected by `.gitignore` (`.env*`). **ROTATE IMMEDIATELY in GitHub Settings**. |

---

## 4. Repository Hardening Verification

1. **`.gitignore` Hardened:**
   - Explicitly configured to ignore `.env*`, `*.env`, `*.env.*`, `*.pem`, `*.key`, `secrets/`, `check_repo*.py`, and `scan_secrets.py`.
2. **`.env.example` Verified:**
   - Contains only sanitized variable names and placeholder strings (`ghp_your_token_here`, `your_gemini_api_key_here`). No real keys.
3. **Public Repo Disambiguation:**
   - Root `README.md` updated to open with:
     > "SupplyGraph: software supply-chain attack-graph, behavioral sandbox and SBOM attestation platform."
   - Added direct hyperlink to `docs/EVIDENCE.md`.
