// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IGroth16Verifier {
    function verifyProof(
        uint256[2]    calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2]    calldata _pC,
        uint256[3]    calldata _pubSignals
    ) external view returns (bool);
}

/// @title  KycMembershipGate
/// @notice Policy wrapper around Groth16Verifier.
///         Enforces three replay-protection layers:
///         1. Merkle root must be in knownRoots (registered by KYC provider)
///         2. nullifierHash = Poseidon(secret, taskCommitment) — task-bound
///         3. consumedNullifiers prevents double-use within the same task
contract KycMembershipGate {
    IGroth16Verifier public immutable verifier;
    address public admin;

    // Layer 1: KYC provider registers valid Merkle roots
    mapping(bytes32 => bool) public knownRoots;

    // Layer 3: consumed nullifiers — one proof per (identity, task)
    mapping(bytes32 => bool) public consumedNullifiers;

    event RootAdded(bytes32 indexed root);
    event RootRevoked(bytes32 indexed root);
    event ProofVerified(
        bytes32 indexed nullifierHash,
        bytes32 indexed taskHashCommitment,
        bytes32 indexed merkleRoot
    );

    error UnknownMerkleRoot(bytes32 root);
    error NullifierAlreadyConsumed(bytes32 nullifier);
    error InvalidProof();

    modifier onlyAdmin() {
        require(msg.sender == admin, "KycGate: not admin");
        _;
    }

    constructor(address _verifier) {
        verifier = IGroth16Verifier(_verifier);
        admin = msg.sender;
    }

    // ── Admin ────────────────────────────────────────────────────────────────

    function addRoot(bytes32 root) external onlyAdmin {
        knownRoots[root] = true;
        emit RootAdded(root);
    }

    function revokeRoot(bytes32 root) external onlyAdmin {
        knownRoots[root] = false;
        emit RootRevoked(root);
    }

    function transferAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "KycGate: zero address");
        admin = newAdmin;
    }

    // ── Verification ─────────────────────────────────────────────────────────

    /// @notice Verify a Groth16 KYC membership proof.
    /// @param _pA  Groth16 pi_a
    /// @param _pB  Groth16 pi_b
    /// @param _pC  Groth16 pi_c
    /// @param merkleRoot        Public signal 0 — must be in knownRoots
    /// @param taskHashCommitment Public signal 1 — hash of the AgentTask
    /// @param nullifierHash     Public signal 2 — Poseidon(secret, taskCommitment)
    /// @return true if proof is valid and nullifier is fresh
    function verify(
        uint256[2]    calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2]    calldata _pC,
        uint256 merkleRoot,
        uint256 taskHashCommitment,
        uint256 nullifierHash
    ) external returns (bool) {
        // Layer 1: Merkle root must be registered by KYC provider
        bytes32 rootKey = bytes32(merkleRoot);
        if (!knownRoots[rootKey]) revert UnknownMerkleRoot(rootKey);

        // Layer 3: Nullifier must not have been consumed
        bytes32 nullifierKey = bytes32(nullifierHash);
        if (consumedNullifiers[nullifierKey]) revert NullifierAlreadyConsumed(nullifierKey);

        // Layer 2 (enforced by circuit): nullifier is bound to taskHashCommitment
        uint256[3] memory pubSignals = [merkleRoot, taskHashCommitment, nullifierHash];
        if (!verifier.verifyProof(_pA, _pB, _pC, pubSignals)) revert InvalidProof();

        // Consume the nullifier — prevent replay within the same task
        consumedNullifiers[nullifierKey] = true;

        emit ProofVerified(
            bytes32(nullifierHash),
            bytes32(taskHashCommitment),
            bytes32(merkleRoot)
        );

        return true;
    }

    /// @notice Read-only check — does NOT consume the nullifier
    function verifyView(
        uint256[2]    calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2]    calldata _pC,
        uint256 merkleRoot,
        uint256 taskHashCommitment,
        uint256 nullifierHash
    ) external view returns (bool) {
        if (!knownRoots[bytes32(merkleRoot)]) return false;
        if (consumedNullifiers[bytes32(nullifierHash)]) return false;
        uint256[3] memory pubSignals = [merkleRoot, taskHashCommitment, nullifierHash];
        return verifier.verifyProof(_pA, _pB, _pC, pubSignals);
    }
}
