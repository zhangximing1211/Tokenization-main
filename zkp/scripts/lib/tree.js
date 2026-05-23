'use strict';
/**
 * Poseidon Merkle Tree (depth = 16)
 * Uses circomlibjs for Poseidon hash — same as the circom circuit.
 */

const { buildPoseidon } = require('circomlibjs');

class PoseidonMerkleTree {
  constructor(levels = 16) {
    this.levels = levels;
    this.leaves = [];
    this._poseidon = null;
    this._F = null;
  }

  async init() {
    this._poseidon = await buildPoseidon();
    this._F = this._poseidon.F;
    return this;
  }

  _hash(a, b) {
    return this._F.toObject(this._poseidon([a, b]));
  }

  // Zero values at each level (empty subtree hashes)
  _zeros() {
    const zeros = [0n];
    for (let i = 1; i <= this.levels; i++) {
      zeros.push(this._hash(zeros[i - 1], zeros[i - 1]));
    }
    return zeros;
  }

  insert(leaf) {
    this.leaves.push(BigInt(leaf));
    return this.leaves.length - 1; // returns index
  }

  getRoot() {
    const zeros = this._zeros();
    let level = [...this.leaves];
    for (let depth = 0; depth < this.levels; depth++) {
      const next = [];
      const size = 1 << (this.levels - depth);
      for (let j = 0; j < size / 2; j++) {
        const left  = level[2 * j]     !== undefined ? level[2 * j]     : zeros[depth];
        const right = level[2 * j + 1] !== undefined ? level[2 * j + 1] : zeros[depth];
        next.push(this._hash(left, right));
      }
      level = next;
    }
    return level[0] !== undefined ? level[0] : zeros[this.levels];
  }

  getProof(index) {
    const zeros = this._zeros();
    const pathElements = [];
    const pathIndices = [];

    let level = [...this.leaves];
    let idx = index;

    for (let depth = 0; depth < this.levels; depth++) {
      const size = 1 << (this.levels - depth);
      // Pad the current level to full size
      const padded = [];
      for (let j = 0; j < size; j++) {
        padded.push(level[j] !== undefined ? level[j] : zeros[depth]);
      }

      const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
      pathElements.push(padded[siblingIdx]);
      pathIndices.push(idx % 2);

      // Build next level
      const next = [];
      for (let j = 0; j < size / 2; j++) {
        next.push(this._hash(padded[2 * j], padded[2 * j + 1]));
      }
      level = next;
      idx = Math.floor(idx / 2);
    }

    return { pathElements, pathIndices };
  }

  // identityCommitment = Poseidon(identitySecret)
  identityCommitment(secret) {
    return this._F.toObject(this._poseidon([BigInt(secret)]));
  }

  // nullifierHash = Poseidon(identitySecret, taskHashCommitment)
  nullifierHash(secret, taskCommitment) {
    return this._F.toObject(this._poseidon([BigInt(secret), BigInt(taskCommitment)]));
  }
}

module.exports = { PoseidonMerkleTree };
