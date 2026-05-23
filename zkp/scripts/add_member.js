#!/usr/bin/env node
'use strict';
/**
 * KYC Provider tool: add an LP to the Merkle registry.
 *
 * Usage:
 *   node scripts/add_member.js --secret <identitySecret> [--registry registry.json]
 *
 * Generates a random identitySecret if --secret is omitted.
 * Writes the updated registry (with new merkleRoot) back to disk.
 */

const fs   = require('fs');
const path = require('path');
const { PoseidonMerkleTree } = require('./lib/tree');

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const registryPath = args['--registry'] || path.join(__dirname, '..', 'registry.json');

  // Load or initialise registry
  let registry = { version: '1.0.0', members: [], merkleRoot: null, treeDepth: 16 };
  if (fs.existsSync(registryPath)) {
    registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
  }

  // Determine identitySecret
  const secret = args['--secret']
    ? BigInt(args['--secret'])
    : randomBigInt();

  // Build tree from existing members + new leaf
  const tree = await new PoseidonMerkleTree(registry.treeDepth).init();
  for (const m of registry.members) {
    tree.insert(BigInt(m.identityCommitment));
  }

  const commitment = tree.identityCommitment(secret);
  const leafIndex  = tree.insert(commitment);
  const root       = tree.getRoot();

  // Persist wallet file for this LP
  const walletDir = path.join(__dirname, '..', 'wallets');
  fs.mkdirSync(walletDir, { recursive: true });
  const walletFile = path.join(walletDir, `lp_${leafIndex}.json`);
  const wallet = {
    leafIndex,
    identitySecret: secret.toString(),
    identityCommitment: commitment.toString(),
    addedAt: new Date().toISOString(),
  };
  fs.writeFileSync(walletFile, JSON.stringify(wallet, null, 2));

  // Update registry
  registry.members.push({
    leafIndex,
    identityCommitment: commitment.toString(),
    addedAt: new Date().toISOString(),
  });
  registry.merkleRoot = root.toString();
  registry.updatedAt  = new Date().toISOString();
  fs.writeFileSync(registryPath, JSON.stringify(registry, null, 2));

  console.log('Member added successfully');
  console.log(`  leafIndex:          ${leafIndex}`);
  console.log(`  identityCommitment: ${commitment}`);
  console.log(`  new merkleRoot:     ${root}`);
  console.log(`  wallet saved to:    ${walletFile}`);
  console.log('');
  console.log('IMPORTANT: keep identitySecret private — never share it.');
  console.log(`  identitySecret: ${secret}`);
}

function randomBigInt() {
  const bytes = require('crypto').randomBytes(31);
  return BigInt('0x' + bytes.toString('hex'));
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) {
      out[argv[i]] = argv[i + 1];
      i++;
    }
  }
  return out;
}

main().catch((err) => { console.error(err); process.exit(1); });
