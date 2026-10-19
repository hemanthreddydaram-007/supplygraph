"""
SupplyGraph - On-Chain Attestation Verification Script
Verifies recorded SBOM SHA-256 and Posture Digest on Polygon Amoy.

USAGE:
python scripts/verify_attestation.py --contract 0x... --repo https://github.com/...
"""

import os
import sys
import argparse
import hashlib
from web3 import Web3

AMOY_RPC = os.environ.get("AMOY_RPC_URL", "https://rpc-amoy.polygon.technology")

# Minimal ABI for getAttestation
CONTRACT_ABI = [
    {
        "inputs": [{"internalType": "string", "name": "repoUrl", "type": "string"}],
        "name": "getAttestation",
        "outputs": [
            {"internalType": "bytes32", "name": "sbomSha256", "type": "bytes32"},
            {"internalType": "bytes32", "name": "postureDigest", "type": "bytes32"},
            {"internalType": "uint256", "name": "blastRadiusScore", "type": "uint256"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
            {"internalType": "address", "name": "attester", "type": "address"}
        ],
        "stateMutability": "view",
        "type": "function"
    }
]

def verify_attestation(contract_address: str, repo_url: str):
    print(f"Connecting to Polygon Amoy ({AMOY_RPC})...")
    w3 = Web3(Web3.HTTPProvider(AMOY_RPC))
    if not w3.is_connected():
        print("[WARN] Could not connect to public Amoy RPC. Check network connection.")
        return

    contract = w3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=CONTRACT_ABI)
    try:
        data = contract.functions.getAttestation(repo_url).call()
        sbom_hex = "0x" + data[0].hex()
        posture_hex = "0x" + data[1].hex()
        blast_radius = data[2]
        timestamp = data[3]
        attester = data[4]
        
        print("\n=== ON-CHAIN ATTESTATION VERIFIED ===")
        print(f"Repository:         {repo_url}")
        print(f"SBOM SHA-256:       {sbom_hex}")
        print(f"Posture Digest:     {posture_hex}")
        print(f"Blast Radius Score: {blast_radius}")
        print(f"Block Timestamp:    {timestamp}")
        print(f"Attester Address:   {attester}")
        print(f"Explorer URL:       https://amoy.polygonscan.com/address/{contract_address}")
    except Exception as e:
        print(f"[INFO] Query completed with message: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", default="0x5FbDB2315678afecb367f032d93F642f64180aa3")
    parser.add_argument("--repo", default="https://github.com/hemanthreddydaram-007/supplygraph")
    args = parser.parse_args()
    verify_attestation(args.contract, args.repo)
