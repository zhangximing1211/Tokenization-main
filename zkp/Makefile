SHELL := /bin/bash
.PHONY: setup test demo clean help

BUILD := build
CIRCUIT := circuits/kyc_membership.circom
ZKEY := $(BUILD)/kyc_membership_final.zkey
WASM := $(BUILD)/kyc_membership_js/kyc_membership.wasm
VKEY := $(BUILD)/verification_key.json

help:
	@echo "Targets:"
	@echo "  make setup   — install deps, compile circuit, run trusted setup"
	@echo "  make test    — run circuit unit tests + Solidity contract tests"
	@echo "  make demo    — run 14-assertion end-to-end verification"
	@echo "  make clean   — remove build artifacts (keeps node_modules)"

setup:
	@bash scripts/setup.sh

test: test-circuit test-contracts

test-circuit:
	@echo "=== Circuit unit tests ==="
	npx mocha tests/test_circuit.js --timeout 120000

test-contracts:
	@echo "=== Solidity contract tests ==="
	forge test -vv

demo:
	@echo "=== End-to-end demo (14 assertions) ==="
	python3 scripts/run_demo.py

clean:
	rm -rf $(BUILD)/kyc_membership.r1cs \
	       $(BUILD)/kyc_membership.sym \
	       $(BUILD)/kyc_membership_0.zkey \
	       $(BUILD)/kyc_membership_js \
	       $(BUILD)/proofs \
	       $(ZKEY) $(VKEY) \
	       out/ cache/
