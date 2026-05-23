pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/mux1.circom";

// Merkle path verifier: verifies that `leaf` is in the tree with root `root`
template MerkleTreeChecker(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal output root;

    component hashers[levels];
    component mux[levels];
    signal levelHashes[levels + 1];

    levelHashes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        // pathIndices[i] must be 0 or 1
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        hashers[i] = Poseidon(2);
        mux[i] = MultiMux1(2);

        // if pathIndices[i] == 0: left = levelHashes[i], right = pathElements[i]
        // if pathIndices[i] == 1: left = pathElements[i], right = levelHashes[i]
        mux[i].c[0][0] <== levelHashes[i];
        mux[i].c[0][1] <== pathElements[i];
        mux[i].c[1][0] <== pathElements[i];
        mux[i].c[1][1] <== levelHashes[i];
        mux[i].s <== pathIndices[i];

        hashers[i].inputs[0] <== mux[i].out[0];
        hashers[i].inputs[1] <== mux[i].out[1];

        levelHashes[i + 1] <== hashers[i].out;
    }

    root <== levelHashes[levels];
}

// Main circuit: KYC Membership Proof
// Private inputs: identitySecret, pathElements, pathIndices
// Public inputs:  merkleRoot, taskHashCommitment, nullifierHash
template KycMembership(levels) {
    // --- Private inputs ---
    signal input identitySecret;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    // --- Public inputs ---
    signal input merkleRoot;
    signal input taskHashCommitment;
    signal input nullifierHash;

    // Constraint 1: identityCommitment = Poseidon(identitySecret)
    component commitmentHasher = Poseidon(1);
    commitmentHasher.inputs[0] <== identitySecret;

    // Constraint 2: Merkle path from identityCommitment reaches merkleRoot
    component tree = MerkleTreeChecker(levels);
    tree.leaf <== commitmentHasher.out;
    for (var i = 0; i < levels; i++) {
        tree.pathElements[i] <== pathElements[i];
        tree.pathIndices[i]   <== pathIndices[i];
    }
    tree.root === merkleRoot;

    // Constraint 3: nullifierHash = Poseidon(identitySecret, taskHashCommitment)
    // Binds the proof to this specific task — cannot be replayed on another task
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== identitySecret;
    nullifierHasher.inputs[1] <== taskHashCommitment;
    nullifierHasher.out === nullifierHash;
}

component main {public [merkleRoot, taskHashCommitment, nullifierHash]} = KycMembership(16);
