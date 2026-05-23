#!/usr/bin/env node
'use strict';
/**
 * snarkjs off-chain verification subprocess.
 * Called by ZkpVerifierService (Python) via subprocess, but can also be used standalone.
 *
 * Usage:
 *   node scripts/verify_offchain.js <vkey.json> <public_signals.json> <proof.json>
 *
 * Exits 0 and prints "OK" on success, exits 1 on failure.
 */

const fs = require('fs');
const snarkjs = require('snarkjs');

async function main() {
  const [, , vkeyPath, signalsPath, proofPath] = process.argv;

  if (!vkeyPath || !signalsPath || !proofPath) {
    console.error('Usage: verify_offchain.js <vkey.json> <public_signals.json> <proof.json>');
    process.exit(1);
  }

  const vkey          = JSON.parse(fs.readFileSync(vkeyPath, 'utf8'));
  const publicSignals = JSON.parse(fs.readFileSync(signalsPath, 'utf8'));
  const proof         = JSON.parse(fs.readFileSync(proofPath, 'utf8'));

  const valid = await snarkjs.groth16.verify(vkey, publicSignals, proof);

  if (valid) {
    console.log('OK');
    process.exit(0);
  } else {
    console.log('INVALID');
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('verify_offchain error:', err.message);
  process.exit(1);
});
