#!/usr/bin/env node
'use strict';
/**
 * LP-side proof generation CLI.
 *
 * Usage:
 *   node scripts/lp_cli.js \
 *     --wallet   wallets/lp_0.json \
 *     --task-hash <hex-or-decimal> \
 *     --registry registry.json \
 *     --wasm     build/kyc_membership_js/kyc_membership.wasm \
 *     --zkey     build/kyc_membership_final.zkey \
 *     [--out     proof_out.json]
 *
 * Outputs a JSON file with { proof, publicSignals } ready for backend submission.
 */

const fs   = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');
const { PoseidonMerkleTree } = require('./lib/tree');

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const walletPath   = require(args['--wallet']   || die('--wallet required'));
  const registryPath = args['--registry'] || path.join(__dirname, '..', 'registry.json');
  const wasmPath     = args['--wasm']     || path.join(__dirname, '..', 'build', 'kyc_membership_js', 'kyc_membership.wasm');
  const zkeyPath     = args['--zkey']     || path.join(__dirname, '..', 'build', 'kyc_membership_final.zkey');
  const outPath      = args['--out']      || path.join(__dirname, '..', 'build', 'proofs', `proof_${Date.now()}.json`);
  const taskHash     = args['--task-hash'] || die('--task-hash required');

  const wallet   = JSON.parse(fs.readFileSync(args['--wallet'], 'utf8'));
  const registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));

  if (!registry.merkleRoot) die('Registry has no merkleRoot — run add_member.js first');

  // Rebuild tree to compute Merkle proof
  const tree = await new PoseidonMerkleTree(registry.treeDepth || 16).init();
  for (const m of registry.members) {
    tree.insert(BigInt(m.identityCommitment));
  }

  const { leafIndex, identitySecret } = wallet;
  const { pathElements, pathIndices } = tree.getProof(leafIndex);
  const merkleRoot    = BigInt(registry.merkleRoot);
  const taskCommit    = BigInt(taskHash);
  const nullifier     = tree.nullifierHash(identitySecret, taskCommit);

  const input = {
    // Private
    identitySecret: identitySecret.toString(),
    pathElements:   pathElements.map(String),
    pathIndices:    pathIndices.map(String),
    // Public
    merkleRoot:          merkleRoot.toString(),
    taskHashCommitment:  taskCommit.toString(),
    nullifierHash:       nullifier.toString(),
  };

  console.log('Generating Groth16 proof …');
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);

  const output = { proof, publicSignals, generatedAt: new Date().toISOString() };
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(output, null, 2));

  console.log('Proof generated');
  console.log(`  merkleRoot:         ${merkleRoot}`);
  console.log(`  taskHashCommitment: ${taskCommit}`);
  console.log(`  nullifierHash:      ${nullifier}`);
  console.log(`  proof saved to:     ${outPath}`);
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) { out[argv[i]] = argv[i + 1]; i++; }
  }
  return out;
}

function die(msg) { console.error('Error:', msg); process.exit(1); }

main().catch((err) => { console.error(err); process.exit(1); });
