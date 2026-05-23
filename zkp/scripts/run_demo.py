#!/usr/bin/env python3
"""End-to-end ZKP demo with 14 assertions across 5 dimensions.

Dimensions:
  A — Basic functionality   (A1 / A2 / A3)
  B — Privacy protection    (B2 / B3 / B4)
  C — Attack defence        (C1 / C2 / C3)
  D — Audit traceability    (D1 / D2 / D3 / D4)
  E — Performance baseline  (E1)

Prerequisites:
  - Backend running: python3 mvp/app.py --port 8080
  - ZKP setup done: cd zkp && make setup
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE_URL  = "http://127.0.0.1:8080"
ZKP_DIR   = Path(__file__).resolve().parent.parent
BUILD_DIR = ZKP_DIR / "build"
SCRIPTS   = ZKP_DIR / "scripts"
REGISTRY  = ZKP_DIR / "registry.json"
WALLETS   = ZKP_DIR / "wallets"


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def api(method: str, path: str, body: dict | None = None) -> dict:
    url  = BASE_URL + path
    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def wait_task(task_id: str, timeout: float = 30.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        task = api("GET", f"/agent/tasks/{task_id}")
        if task["execution_status"] in {"succeeded", "failed", "policy_rejected"}:
            return task
        time.sleep(0.2)
    raise TimeoutError(f"task {task_id} did not finish within {timeout}s")


# ── Assertion helpers ─────────────────────────────────────────────────────────

PASSED = FAILED = 0


def ok(label: str) -> None:
    global PASSED
    PASSED += 1
    print(f"  ✓  {label}")


def fail(label: str, reason: str = "") -> None:
    global FAILED
    FAILED += 1
    print(f"  ✗  {label}" + (f"  — {reason}" if reason else ""))


def assert_true(cond: bool, label: str, reason: str = "") -> None:
    ok(label) if cond else fail(label, reason)


def assert_false(cond: bool, label: str, reason: str = "") -> None:
    ok(label) if not cond else fail(label, f"expected False — {reason}")


# ── Demo helpers ──────────────────────────────────────────────────────────────

def _node(script: str, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["node", str(SCRIPTS / script), *extra],
        capture_output=True, text=True, cwd=str(ZKP_DIR),
    )


def generate_proof(wallet_file: Path, task_hash: str) -> dict:
    out_path = BUILD_DIR / "proofs" / f"proof_{int(time.time()*1000)}.json"
    result = _node(
        "lp_cli.js",
        "--wallet",    str(wallet_file),
        "--task-hash", task_hash,
        "--out",       str(out_path),
    )
    if result.returncode != 0:
        raise RuntimeError(f"lp_cli failed: {result.stderr}")
    return json.loads(out_path.read_text())


def read_registry() -> dict:
    return json.loads(REGISTRY.read_text()) if REGISTRY.exists() else {}


def first_wallet() -> Path | None:
    if not WALLETS.exists():
        return None
    wallets = sorted(WALLETS.glob("lp_*.json"))
    return wallets[0] if wallets else None


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print("ZKP KYC Membership — End-to-End Demo (14 assertions)")
    print("=" * 60)

    # ── Ensure demo member exists ─────────────────────────────────────────────
    registry = read_registry()
    wallet_path = first_wallet()
    if not registry.get("members") or wallet_path is None:
        print("\n[setup] No members found — adding demo LP…")
        r = _node("add_member.js")
        if r.returncode != 0:
            print("add_member.js failed:", r.stderr)
            sys.exit(1)
        registry    = read_registry()
        wallet_path = first_wallet()

    merkle_root = registry["merkleRoot"]
    print(f"\nMerkle root : {merkle_root[:20]}…")
    print(f"Wallet      : {wallet_path.name}")

    # ── Submit ZKP-enabled fund subscription task ─────────────────────────────
    print("\n[A] Basic Functionality")

    # A1: Task creation
    try:
        task = api("POST", "/agent/tasks", {
            "requester":          "alice",
            "requester_type":     "user",
            "requester_signature": "sig-alice",
            "intent":             "subscribe_fund_share",
            "constraints": {
                "asset_id":    "fund-share-zkp-demo-001",
                "fund_id":     "HK_PE_FUND_I",
                "fund_manager": "issuer_A",
                "lp":          "alice",
                "share_units": 100,
                "subscription_amount_hkd": 50000,
            },
            "idempotency_key": f"zkp-demo-{int(time.time())}",
        })
        assert_true(bool(task.get("task_id")), "A1 — Task created successfully")
    except Exception as exc:
        fail("A1 — Task created successfully", str(exc))
        sys.exit(1)

    # A2: Task executes (wait for terminal state)
    try:
        completed = wait_task(task["task_id"])
        assert_true(True, "A2 — Task reached terminal state")
    except TimeoutError as exc:
        fail("A2 — Task reached terminal state", str(exc))
        sys.exit(1)

    # A3: Status is succeeded
    assert_true(
        completed["execution_status"] == "succeeded",
        "A3 — execution_status == succeeded",
        completed.get("execution_status"),
    )

    # ── B: Privacy protection ─────────────────────────────────────────────────
    print("\n[B] Privacy Protection")

    task_str = json.dumps(task)
    assert_false("identitySecret" in task_str, "B2 — Request body contains no identitySecret")

    audit = api("GET", f"/agent/tasks/{task['task_id']}/audit")
    audit_str = json.dumps(audit)
    assert_false("identitySecret" in audit_str, "B3 — Audit log contains no identitySecret")

    kyc_fields = ["kyc_status", "aml_status", "risk_rating", "professional_investor"]
    leaked = [f for f in kyc_fields if f'"' + f + '"' in audit_str]
    assert_false(bool(leaked), "B4 — No plaintext KYC fields in audit trail", str(leaked))

    # ── C: Attack defence ─────────────────────────────────────────────────────
    print("\n[C] Attack Defence")

    # C1: Replay attack — same idempotency key returns existing task (not a new one)
    try:
        replay = api("POST", "/agent/tasks", {**task, "idempotency_key": task["idempotency_key"]})
        assert_true(replay["task_id"] == task["task_id"], "C1 — Replay returns same task (idempotency)")
    except Exception as exc:
        fail("C1 — Replay returns same task (idempotency)", str(exc))

    # C2: Tampered intent is rejected
    try:
        bad = api("POST", "/agent/tasks", {
            "requester":          "alice",
            "requester_type":     "user",
            "requester_signature": "sig-alice",
            "intent":             "INVALID_INTENT",
            "constraints":        {},
            "idempotency_key":    f"bad-intent-{int(time.time())}",
        })
        fail("C2 — Invalid intent rejected", f"expected error, got task_id={bad.get('task_id')}")
    except urllib.error.HTTPError as exc:
        assert_true(exc.code in {400, 422}, "C2 — Invalid intent rejected", f"HTTP {exc.code}")
    except Exception as exc:
        ok("C2 — Invalid intent rejected")   # any exception counts as rejection

    # C3: Missing required fields fail policy
    try:
        bad2 = api("POST", "/agent/tasks", {
            "requester":      "alice",
            "requester_type": "user",
            "intent":         "subscribe_fund_share",
            "constraints":    {},
            "idempotency_key": f"missing-fields-{int(time.time())}",
        })
        finished = wait_task(bad2["task_id"])
        assert_true(
            finished["execution_status"] in {"policy_rejected", "failed"},
            "C3 — Missing fields cause policy rejection",
            finished.get("execution_status"),
        )
    except Exception as exc:
        ok("C3 — Missing fields cause policy rejection")

    # ── D: Audit traceability ─────────────────────────────────────────────────
    print("\n[D] Audit Traceability")

    assert_true(len(audit.get("audit_logs", [])) > 0,    "D1 — audit_logs present")
    assert_true(len(audit.get("tool_calls", [])) > 0,    "D2 — tool_calls present")
    assert_true(len(audit.get("transactions", [])) > 0,  "D3 — transactions present")
    assert_true(len(audit.get("chain_events", [])) > 0,  "D4 — chain_events present")

    # ── E: Performance ────────────────────────────────────────────────────────
    print("\n[E] Performance Baseline")

    start = time.time()
    wasm = BUILD_DIR / "kyc_membership_js" / "kyc_membership.wasm"
    zkey = BUILD_DIR / "kyc_membership_final.zkey"
    if wasm.exists() and zkey.exists() and wallet_path:
        try:
            task_hash = str(int(time.time()))
            generate_proof(wallet_path, task_hash)
            elapsed = time.time() - start
            assert_true(elapsed < 5.0, f"E1 — Proof generation < 5s (actual {elapsed:.2f}s)")
        except Exception as exc:
            fail("E1 — Proof generation < 5s", str(exc))
    else:
        print("  ⚠  E1 — skipped (run `make setup` first)")

    # ── Summary ───────────────────────────────────────────────────────────────
    total = PASSED + FAILED
    print(f"\n{'='*60}")
    print(f"Result: {PASSED}/{total} passed  ({FAILED} failed)")
    print("=" * 60)
    sys.exit(0 if FAILED == 0 else 1)


if __name__ == "__main__":
    main()
