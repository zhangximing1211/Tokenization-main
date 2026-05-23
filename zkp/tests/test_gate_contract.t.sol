// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../contracts/KycMembershipGate.sol";

/// @dev Minimal mock verifier — always returns the configured value.
contract MockGroth16Verifier {
    bool public shouldPass = true;

    function setResult(bool v) external { shouldPass = v; }

    function verifyProof(
        uint256[2]    calldata,
        uint256[2][2] calldata,
        uint256[2]    calldata,
        uint256[3]    calldata
    ) external view returns (bool) {
        return shouldPass;
    }
}

contract KycMembershipGateTest is Test {
    MockGroth16Verifier verifier;
    KycMembershipGate   gate;

    uint256[2]    pA;
    uint256[2][2] pB;
    uint256[2]    pC;

    bytes32 constant ROOT     = bytes32(uint256(1));
    uint256 constant MERKLE   = uint256(ROOT);
    uint256 constant TASK     = uint256(keccak256("task-001"));
    uint256 constant NULLIFIER = uint256(keccak256("nullifier-001"));

    function setUp() public {
        verifier = new MockGroth16Verifier();
        gate     = new KycMembershipGate(address(verifier));
        gate.addRoot(ROOT);
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    function test_validProofSucceeds() public {
        bool ok = gate.verify(pA, pB, pC, MERKLE, TASK, NULLIFIER);
        assertTrue(ok);
    }

    function test_nullifierConsumedAfterVerify() public {
        gate.verify(pA, pB, pC, MERKLE, TASK, NULLIFIER);
        assertTrue(gate.consumedNullifiers(bytes32(NULLIFIER)));
    }

    // ── Replay protection ─────────────────────────────────────────────────────

    function test_replayRejected() public {
        gate.verify(pA, pB, pC, MERKLE, TASK, NULLIFIER);
        vm.expectRevert(
            abi.encodeWithSelector(
                KycMembershipGate.NullifierAlreadyConsumed.selector,
                bytes32(NULLIFIER)
            )
        );
        gate.verify(pA, pB, pC, MERKLE, TASK, NULLIFIER);
    }

    function test_differentNullifierAllowed() public {
        uint256 n2 = uint256(keccak256("nullifier-002"));
        gate.verify(pA, pB, pC, MERKLE, TASK, NULLIFIER);
        bool ok = gate.verify(pA, pB, pC, MERKLE, TASK, n2);
        assertTrue(ok);
    }

    // ── Unknown root ──────────────────────────────────────────────────────────

    function test_unknownRootRejected() public {
        bytes32 fakeRoot = bytes32(uint256(999));
        vm.expectRevert(
            abi.encodeWithSelector(
                KycMembershipGate.UnknownMerkleRoot.selector,
                fakeRoot
            )
        );
        gate.verify(pA, pB, pC, uint256(fakeRoot), TASK, NULLIFIER);
    }

    // ── Invalid proof ─────────────────────────────────────────────────────────

    function test_invalidProofRejected() public {
        verifier.setResult(false);
        vm.expectRevert(KycMembershipGate.InvalidProof.selector);
        gate.verify(pA, pB, pC, MERKLE, TASK, NULLIFIER);
    }

    // ── Admin functions ───────────────────────────────────────────────────────

    function test_revokeRoot() public {
        gate.revokeRoot(ROOT);
        vm.expectRevert(
            abi.encodeWithSelector(
                KycMembershipGate.UnknownMerkleRoot.selector,
                ROOT
            )
        );
        gate.verify(pA, pB, pC, MERKLE, TASK, NULLIFIER);
    }

    function test_nonAdminCannotAddRoot() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert("KycGate: not admin");
        gate.addRoot(bytes32(uint256(2)));
    }

    function test_transferAdmin() public {
        address newAdmin = address(0x1234);
        gate.transferAdmin(newAdmin);
        assertEq(gate.admin(), newAdmin);
    }

    // ── verifyView (read-only, does not consume nullifier) ────────────────────

    function test_verifyViewDoesNotConsumeNullifier() public {
        gate.verifyView(pA, pB, pC, MERKLE, TASK, NULLIFIER);
        assertFalse(gate.consumedNullifiers(bytes32(NULLIFIER)));
    }

    function test_verifyViewReturnsFalseAfterConsumption() public {
        gate.verify(pA, pB, pC, MERKLE, TASK, NULLIFIER);
        bool ok = gate.verifyView(pA, pB, pC, MERKLE, TASK, NULLIFIER);
        assertFalse(ok);
    }
}
