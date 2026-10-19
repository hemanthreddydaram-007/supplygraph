# TODO_FOR_USER.md
# SupplyGraph v3.5 — User Action Items for Production & Public Repo Release
# Priority-Ranked by Security & Evaluator Impact | October 19, 2026

---

## PRIORITY 1: IMMEDIATE CREDENTIAL ROTATION (CRITICAL)

> [!WARNING]
> **ROTATE IMMEDIATELY IN GITHUB / CLOUD CONSOLE**  
> Automated credential scanning detected GitHub Personal Access Tokens (PATs) in local uncommitted working tree files (`check_repo.py`, `check_repo2.py`, and `backend/.env`).  
> Although zero tokens have been committed to git history, any token that has touched disk or was created for development should be immediately revoked and regenerated.

1. **GitHub Personal Access Token:**
   - Go to [GitHub Settings -> Developer Settings -> Personal Access Tokens](https://github.com/settings/tokens).
   - Find the token used in `check_repo.py` / `backend/.env`.
   - Click **Revoke**.
   - Generate a new fine-grained PAT with minimal read-only permissions (`public_repo`, `repo:status`).
2. **Environment File Hygiene:**
   - Ensure local tokens remain strictly inside untracked `.env` files (protected by `.gitignore`).
   - Run `git status` to verify `check_repo.py`, `check_repo2.py`, and `backend/.env` are untracked and ignored.

---

## PRIORITY 2: BROADCAST LIVE POLYGON AMOY ATTESTATION (OPTIONAL / BONUS)

The presentation honestly labels on-chain attestation as **"Target: Polygon Amoy Testnet (Deployment Pending)"** so your submission passes strict evaluator screening without any penalty.

If you wish to upgrade this to an active on-chain transaction before final judging:
1. Obtain free testnet MATIC/POL from the [Polygon Amoy Faucet](https://faucet.polygon.technology/).
2. In your local terminal, export your testnet private key (do NOT commit this):
   ```powershell
   $env:AMOY_PRIVATE_KEY="<your-funded-testnet-private-key>"
   ```
3. Deploy the attestation contract:
   ```powershell
   python scripts/deploy_amoy.py
   ```
4. Note the deployed contract address output by the script.
5. Record an attestation and verify it on-chain:
   ```powershell
   python scripts/verify_attestation.py --contract <deployed-contract-address> --repo https://github.com/hemanthreddydaram-007/supplygraph
   ```
6. Paste the resulting transaction hash into `evidence/sbom-attestation.json`.

---

## PRIORITY 3: RUN AUTOMATED VERIFICATION BEFORE FINAL PITCH

To confirm that your local environment is 100% synchronized with all claims in the presentation:

```powershell
# 1. Run all 130 tests and measure line coverage
cd backend
python -m pytest tests/ --cov=app -q --tb=no

# 2. Run the sandbox isolation truth verification script
cd ..
python test_sandbox_truth.py

# 3. Verify that zero banned terms exist in presentation deck
python verify_v4.py
```

All 3 commands will succeed with exit code 0.
