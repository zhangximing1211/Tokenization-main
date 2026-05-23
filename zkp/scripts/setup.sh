#!/usr/bin/env bash
# One-click ZKP setup: install deps, compile circuit, trusted setup, export verifier.
set -euo pipefail

cd "$(dirname "$0")/.."
ZKP_DIR="$(pwd)"
BUILD="$ZKP_DIR/build"
mkdir -p "$BUILD/kyc_membership_js" "$BUILD/proofs"

echo "=== [1/6] npm install ==="
npm install

echo "=== [2/6] Download Powers of Tau (ptau14) ==="
PTAU="$BUILD/pot14_final.ptau"
if [ ! -f "$PTAU" ]; then
  curl -L -o "$PTAU" \
    https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_14.ptau
fi

echo "=== [3/6] Compile circom circuit ==="
npx circom circuits/kyc_membership.circom \
  --r1cs --wasm --sym \
  -l node_modules \
  -o "$BUILD"

echo "=== [4/6] Groth16 trusted setup — Phase 2 ==="
R1CS="$BUILD/kyc_membership.r1cs"
ZKEY0="$BUILD/kyc_membership_0.zkey"
ZKEY_FINAL="$BUILD/kyc_membership_final.zkey"

npx snarkjs groth16 setup "$R1CS" "$PTAU" "$ZKEY0"
npx snarkjs zkey contribute "$ZKEY0" "$ZKEY_FINAL" \
  --name="Demo contribution" -v -e="$(date +%s%N)"

echo "=== [5/6] Export verification key ==="
npx snarkjs zkey export verificationkey "$ZKEY_FINAL" "$BUILD/verification_key.json"

echo "=== [6/6] Export Solidity verifier ==="
npx snarkjs zkey export solidityverifier "$ZKEY_FINAL" contracts/Groth16Verifier.sol

echo ""
echo "Setup complete!"
echo "  verification_key : build/verification_key.json"
echo "  zkey             : build/kyc_membership_final.zkey"
echo "  wasm             : build/kyc_membership_js/kyc_membership.wasm"
echo "  Groth16Verifier  : contracts/Groth16Verifier.sol (regenerated)"
