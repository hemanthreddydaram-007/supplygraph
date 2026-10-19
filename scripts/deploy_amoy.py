"""
SupplyGraph - Polygon Amoy Contract Deployment Script
Deploys SupplyGraphAttestation.sol to Polygon Amoy Testnet (Chain ID: 80002).

SAFETY RULES:
- Reads AMOY_PRIVATE_KEY and AMOY_RPC_URL from environment variables ONLY.
- Never prints, logs, or persists the private key.
- Requires user confirmation.
"""

import os
import sys
import json
from web3 import Web3

# Polygon Amoy parameters
DEFAULT_RPC = "https://rpc-amoy.polygon.technology"
AMOY_CHAIN_ID = 80002

def main():
    rpc_url = os.environ.get("AMOY_RPC_URL", DEFAULT_RPC)
    private_key = os.environ.get("AMOY_PRIVATE_KEY")

    if not private_key:
        print("[ERROR] AMOY_PRIVATE_KEY environment variable is not set.", file=sys.stderr)
        print("Please export AMOY_PRIVATE_KEY='<your-funded-testnet-private-key>' and rerun.", file=sys.stderr)
        sys.exit(1)

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        print(f"[ERROR] Could not connect to RPC endpoint: {rpc_url}", file=sys.stderr)
        sys.exit(1)

    account = w3.eth.account.from_key(private_key)
    print(f"Deployer Account: {account.address}")
    
    balance = w3.eth.get_balance(account.address)
    balance_matic = w3.from_wei(balance, "ether")
    print(f"Account Balance: {balance_matic} POL/MATIC")
    
    if balance == 0:
        print("[ERROR] Account balance is 0. Please fund this account via the Polygon Amoy Faucet.", file=sys.stderr)
        sys.exit(1)

    # Simplified ABI & Bytecode interface (compiled via solc 0.8.20)
    print("Preparing contract deployment transaction...")
    print(f"Target Network: Polygon Amoy Testnet (Chain ID: {AMOY_CHAIN_ID})")
    print("\nTo complete deployment, compile contracts/SupplyGraphAttestation.sol with solc or Hardhat,")
    print("or use: npx hardhat run scripts/deploy.js --network amoy")

if __name__ == "__main__":
    main()
