"""Off-chain Groth16 verifier service (Python).

Provides fail-fast pre-verification before the on-chain final arbiter.
Calls snarkjs via subprocess so no native bindings are required.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from typing import Any


class ZkpVerifierService:
    def __init__(
        self,
        verification_key_path: str,
        snarkjs_bin: str = "snarkjs",
    ) -> None:
        self.verification_key_path = verification_key_path
        self.snarkjs_bin = snarkjs_bin
        self._known_roots: set[str] = set()
        self._consumed_nullifiers: set[str] = set()

        with open(verification_key_path) as fh:
            self.verification_key = json.load(fh)

    # ── Registry ──────────────────────────────────────────────────────────────

    def add_root(self, root: str) -> None:
        self._known_roots.add(str(root))

    def revoke_root(self, root: str) -> None:
        self._known_roots.discard(str(root))

    def is_nullifier_consumed(self, nullifier_hash: str) -> bool:
        return str(nullifier_hash) in self._consumed_nullifiers

    # ── Verification ─────────────────────────────────────────────────────────

    def verify(
        self,
        proof: dict[str, Any],
        public_signals: list[str],
        task_hash_commitment: str,
    ) -> dict[str, Any]:
        """Verify a Groth16 KYC membership proof off-chain.

        public_signals order matches the circuit: [merkleRoot, taskHashCommitment, nullifierHash]

        Raises ValueError with a reason code on any failure.
        Returns a dict with verified=True and audit fields on success.
        """
        if len(public_signals) != 3:
            raise ValueError("invalid_public_signals_length")

        merkle_root = str(public_signals[0])
        task_commitment_signal = str(public_signals[1])
        nullifier_hash = str(public_signals[2])

        # Layer 1: Merkle root must be registered
        if merkle_root not in self._known_roots:
            raise ValueError(f"unknown_merkle_root:{merkle_root}")

        # Layer 2: taskHashCommitment in proof must match the caller's expectation
        if task_commitment_signal != str(task_hash_commitment):
            raise ValueError("task_hash_commitment_mismatch")

        # Layer 3: Nullifier must not be consumed
        if nullifier_hash in self._consumed_nullifiers:
            raise ValueError(f"nullifier_already_consumed:{nullifier_hash}")

        # Groth16 proof verification via snarkjs subprocess
        if not self._verify_groth16(proof, public_signals):
            raise ValueError("invalid_zkp_proof")

        # Consume nullifier (off-chain mirror — on-chain contract is the authority)
        self._consumed_nullifiers.add(nullifier_hash)

        proof_hash = hashlib.sha256(
            json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

        return {
            "verified": True,
            "merkle_root": merkle_root,
            "nullifier_hash": nullifier_hash,
            "task_hash_commitment": task_commitment_signal,
            "proof_hash": proof_hash,
        }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _verify_groth16(
        self,
        proof: dict[str, Any],
        public_signals: list[str],
    ) -> bool:
        proof_fd, proof_path = tempfile.mkstemp(suffix=".json")
        signals_fd, signals_path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(proof_fd, "w") as fh:
                json.dump(proof, fh)
            with os.fdopen(signals_fd, "w") as fh:
                json.dump(public_signals, fh)

            result = subprocess.run(
                [
                    self.snarkjs_bin,
                    "groth16", "verify",
                    self.verification_key_path,
                    signals_path,
                    proof_path,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.returncode == 0 and "OK" in result.stdout
        except subprocess.TimeoutExpired:
            raise ValueError("zkp_verification_timeout")
        except FileNotFoundError:
            raise ValueError(f"snarkjs_not_found:{self.snarkjs_bin}")
        finally:
            try:
                os.unlink(proof_path)
            except OSError:
                pass
            try:
                os.unlink(signals_path)
            except OSError:
                pass


def build_zkp_verifier(zkp_dir: str | None = None) -> ZkpVerifierService | None:
    """Return a ZkpVerifierService if the verification key exists, else None."""
    base = zkp_dir or os.path.join(os.path.dirname(__file__), "..", "build")
    vk_path = os.path.normpath(os.path.join(base, "verification_key.json"))
    if not os.path.exists(vk_path):
        return None
    snarkjs = os.path.join(
        os.path.dirname(__file__), "..", "node_modules", ".bin", "snarkjs"
    )
    return ZkpVerifierService(
        verification_key_path=vk_path,
        snarkjs_bin=snarkjs if os.path.exists(snarkjs) else "snarkjs",
    )
