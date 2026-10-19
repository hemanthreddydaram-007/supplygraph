// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SupplyGraphAttestation
 * @dev Cryptographic SBOM & Security Posture Digest Anchor for Software Supply Chain Integrity.
 * Deployed to Polygon Amoy Testnet (Chain ID: 80002).
 */
contract SupplyGraphAttestation {
    address public owner;

    struct AttestationRecord {
        string repoUrl;
        bytes32 sbomSha256;
        bytes32 postureDigest;
        uint256 blastRadiusScore;
        uint256 timestamp;
        address attester;
    }

    // Mapping from repository URL hash to AttestationRecord
    mapping(bytes32 => AttestationRecord) public attestations;
    bytes32[] public repositoryHashes;

    event AttestationAnchored(
        bytes32 indexed repoHash,
        string repoUrl,
        bytes32 sbomSha256,
        bytes32 postureDigest,
        uint256 blastRadiusScore,
        uint256 timestamp,
        address indexed attester
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Only contract owner can invoke this function");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /**
     * @dev Record a tamper-evident SBOM SHA-256 digest and posture fingerprint.
     */
    function recordAttestation(
        string calldata repoUrl,
        bytes32 sbomSha256,
        bytes32 postureDigest,
        uint256 blastRadiusScore
    ) external returns (bytes32) {
        bytes32 repoHash = keccak256(abi.encodePacked(repoUrl));

        if (attestations[repoHash].timestamp == 0) {
            repositoryHashes.push(repoHash);
        }

        attestations[repoHash] = AttestationRecord({
            repoUrl: repoUrl,
            sbomSha256: sbomSha256,
            postureDigest: postureDigest,
            blastRadiusScore: blastRadiusScore,
            timestamp: block.timestamp,
            attester: msg.sender
        });

        emit AttestationAnchored(
            repoHash,
            repoUrl,
            sbomSha256,
            postureDigest,
            blastRadiusScore,
            block.timestamp,
            msg.sender
        );

        return repoHash;
    }

    /**
     * @dev Retrieve attestation record by repository URL.
     */
    function getAttestation(string calldata repoUrl) external view returns (
        bytes32 sbomSha256,
        bytes32 postureDigest,
        uint256 blastRadiusScore,
        uint256 timestamp,
        address attester
    ) {
        bytes32 repoHash = keccak256(abi.encodePacked(repoUrl));
        AttestationRecord memory record = attestations[repoHash];
        require(record.timestamp != 0, "No attestation found for repository");
        return (
            record.sbomSha256,
            record.postureDigest,
            record.blastRadiusScore,
            record.timestamp,
            record.attester
        );
    }
}
