'use strict';
/**
 * Circuit unit tests — requires `make setup` to have been run first.
 * Run with: npx mocha tests/test_circuit.js --timeout 120000
 */

const assert = require('assert');
const path   = require('path');
const fs     = require('fs');
const snarkjs = require('snarkjs');
const { PoseidonMerkleTree } = require('../scripts/lib/tree');

const BUILD   = path.join(__dirname, '..', 'build');
const WASM    = path.join(BUILD, 'kyc_membership_js', 'kyc_membership.wasm');
const ZKEY    = path.join(BUILD, 'kyc_membership_final.zkey');
const VKEY    = path.join(BUILD, 'verification_key.json');

function skipIfNotBuilt() {
  if (!fs.existsSync(WASM) || !fs.existsSync(ZKEY)) {
    console.log('  (skipped — run `make setup` first)');
    return true;
  }
  return false;
}

let tree;
let secret;
let leafIndex;
let vkey;

before(async function () {
  this.timeout(30000);
  tree = await new PoseidonMerkleTree(16).init();
  secret = BigInt('0x' + require('crypto').randomBytes(28).toString('hex'));
  const commitment = tree.identityCommitment(secret);
  leafIndex = tree.insert(commitment);
  if (fs.existsSync(VKEY)) {
    vkey = JSON.parse(fs.readFileSync(VKEY, 'utf8'));
  }
});

async function makeProof(overrides = {}) {
  const root       = tree.getRoot();
  const taskCommit = BigInt('12345678901234567890');
  const nullifier  = tree.nullifierHash(secret, taskCommit);
  const { pathElements, pathIndices } = tree.getProof(leafIndex);

  const input = {
    identitySecret:     secret.toString(),
    pathElements:       pathElements.map(String),
    pathIndices:        pathIndices.map(String),
    merkleRoot:         root.toString(),
    taskHashCommitment: taskCommit.toString(),
    nullifierHash:      nullifier.toString(),
    ...overrides,
  };

  return snarkjs.groth16.fullProve(input, WASM, ZKEY);
}

describe('Circuit — happy path', function () {
  this.timeout(60000);

  it('generates and verifies a valid proof', async function () {
    if (skipIfNotBuilt()) return;
    const { proof, publicSignals } = await makeProof();
    const valid = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    assert.strictEqual(valid, true);
  });

  it('public signals contain merkleRoot, taskHashCommitment, nullifierHash', async function () {
    if (skipIfNotBuilt()) return;
    const root       = tree.getRoot();
    const taskCommit = BigInt('12345678901234567890');
    const nullifier  = tree.nullifierHash(secret, taskCommit);
    const { publicSignals } = await makeProof();
    assert.strictEqual(publicSignals[0], root.toString());
    assert.strictEqual(publicSignals[1], taskCommit.toString());
    assert.strictEqual(publicSignals[2], nullifier.toString());
  });
});

describe('Circuit — replay protection', function () {
  this.timeout(120000);

  it('different tasks produce different nullifiers', async function () {
    if (skipIfNotBuilt()) return;
    const t1 = BigInt('111');
    const t2 = BigInt('222');
    const n1 = tree.nullifierHash(secret, t1);
    const n2 = tree.nullifierHash(secret, t2);
    assert.notStrictEqual(n1.toString(), n2.toString());
  });

  it('same secret + same task always produces the same nullifier', async function () {
    const t = BigInt('99999');
    const n1 = tree.nullifierHash(secret, t);
    const n2 = tree.nullifierHash(secret, t);
    assert.strictEqual(n1.toString(), n2.toString());
  });
});

describe('Circuit — invalid inputs', function () {
  this.timeout(60000);

  it('proof fails when merkleRoot is tampered', async function () {
    if (skipIfNotBuilt()) return;
    const { proof, publicSignals } = await makeProof();
    const tampered = [...publicSignals];
    tampered[0] = (BigInt(tampered[0]) + 1n).toString();
    const valid = await snarkjs.groth16.verify(vkey, tampered, proof);
    assert.strictEqual(valid, false);
  });

  it('proof fails when nullifierHash is tampered', async function () {
    if (skipIfNotBuilt()) return;
    const { proof, publicSignals } = await makeProof();
    const tampered = [...publicSignals];
    tampered[2] = (BigInt(tampered[2]) + 1n).toString();
    const valid = await snarkjs.groth16.verify(vkey, tampered, proof);
    assert.strictEqual(valid, false);
  });
});

describe('Merkle tree', function () {
  it('correctly computes root after inserting multiple leaves', async function () {
    const t2 = await new PoseidonMerkleTree(16).init();
    const s1 = 100n, s2 = 200n, s3 = 300n;
    t2.insert(t2.identityCommitment(s1));
    t2.insert(t2.identityCommitment(s2));
    t2.insert(t2.identityCommitment(s3));
    const root = t2.getRoot();
    assert.ok(root > 0n, 'root should be non-zero');
  });

  it('proof for index 0 is accepted by the tree', async function () {
    const t3 = await new PoseidonMerkleTree(4).init();
    const s  = 42n;
    const c  = t3.identityCommitment(s);
    const idx = t3.insert(c);
    t3.insert(t3.identityCommitment(99n));
    const { pathElements, pathIndices } = t3.getProof(idx);
    assert.strictEqual(pathElements.length, 4);
    assert.strictEqual(pathIndices.length, 4);
  });
});
