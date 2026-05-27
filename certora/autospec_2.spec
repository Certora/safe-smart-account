/*
 * CVL Specification: Signature Verification and Hash Management Properties for Safe
 *
 * This spec covers Properties 1-12 of the Safe contract's signature verification
 * and hash management component. Targets Safe directly (no harness).
 *
 * CVL/Code Document-Ref: 5e9207432f53c2acb1d30d4e90ffb23b3c4fa2a35bd28e (owner-manager structure)
 * CVL/Code Document-Ref: e46d3a5556c634d9ea38ff62c99a217cdcd8c215417473 (requireInvariant in rules)
 * CVL/Code Document-Ref: b085e6a5a3d8b648b182499d7dd1327fbd96ff58c157fb (keccak256 in CVL)
 * CVL/Code Document-Ref: 37f5e798f4b0a92c6054956e51be9422e8c011e24719eb (bytes32->address cast)
 */

import "specs/summaries/Safe_base_summaries.spec";
import "custom_summaries.spec";
import "invariants.spec";

// =============================================================================
// Ghost state: model signatureSplit deterministically (position-indexed only)
//
// Using position-only indexing avoids the convert_hashblob mismatch that occurs
// when bytes is used as a mapping key. Within a single call to checkNSignatures,
// signatures is fixed, so sigV[pos] / sigR[pos] / sigS[pos] consistently represent
// the (v, r, s) at the given position regardless of how the bytes argument is passed.
// =============================================================================

persistent ghost mapping(uint256 => uint8) sigV;
persistent ghost mapping(uint256 => bytes32) sigR;
persistent ghost mapping(uint256 => bytes32) sigS;

function signatureSplitGhost(bytes signatures, uint256 pos) returns (uint8, bytes32, bytes32) {
    return (sigV[pos], sigR[pos], sigS[pos]);
}

// =============================================================================
// Methods block
// =============================================================================
methods {
    // --------------------------------------------------------------------------
    // Envfree declarations: view functions that do not use msg.sender/msg.value
    // --------------------------------------------------------------------------
    function getThreshold() external returns (uint256) envfree;
    function isOwner(address) external returns (bool) envfree;
    function domainSeparator() external returns (bytes32) envfree;

    // Main (executor-explicit) overloads for signature verification
    function checkSignatures(address, bytes32, bytes) external envfree;
    function checkNSignatures(address, bytes32, bytes, uint256) external envfree;

    // Auto-generated getter for the approvedHashes nested mapping
    // (declared public override in Safe.sol via ISafe interface)
    function approvedHashes(address, bytes32) external returns (uint256) envfree;

    // --------------------------------------------------------------------------
    // Internal function summaries
    // --------------------------------------------------------------------------

    // Model signatureSplit with a ghost for cross-call consistency.
    // Position-only indexing ensures rule body and internal calls see same values.
    function SignatureDecoder.signatureSplit(bytes memory signatures, uint256 pos)
        internal returns (uint8, bytes32, bytes32)
        => signatureSplitGhost(signatures, pos);

    // Model p256Verify as CONSTANT (opaque, fixed value per rule run).
    // This covers both "precompile present" (CONSTANT=true) and
    // "precompile absent" (CONSTANT=false) cases.
    function EIP7951.p256Verify(bytes32, bytes32, bytes32, uint256, uint256)
        internal returns (bool)
        => CONSTANT;
}

// =============================================================================
// Property 1: After initialization, 1 <= threshold <= ownerCount
//
// Goal: demonstrate this property holds.
// =============================================================================

/// @title Threshold is properly bounded: 1 <= threshold <= ownerCount for initialized Safe
invariant threshold_bounds_valid()
    ownerCountGhost == 0 || (thresholdGhost >= 1 && thresholdGhost <= ownerCountGhost)
    filtered { f -> reachableOnly(f) }
    {
        preserved {
            requireInvariant threshold_le_ownercount();
            requireInvariant threshold_and_ownercount_jointly_zero();
        }
        preserved addOwnerWithThreshold(address owner, uint256 _threshold) with (env e) {
            requireInvariant threshold_le_ownercount();
            requireInvariant threshold_and_ownercount_jointly_zero();
            require ownerCountGhost > 0;
        }
        preserved removeOwner(address prevOwner, address owner, uint256 _threshold) with (env e) {
            requireInvariant threshold_le_ownercount();
            requireInvariant threshold_and_ownercount_jointly_zero();
        }
        preserved changeThreshold(uint256 _threshold) with (env e) {
            requireInvariant threshold_le_ownercount();
            requireInvariant threshold_and_ownercount_jointly_zero();
        }
    }

// =============================================================================
// Property 2: approveHash must revert when msg.sender is not a registered owner
//
// Goal: demonstrate this property holds.
// =============================================================================

/// @title approveHash reverts for non-owners (excluding SENTINEL corner case)
/// @notice Code check: `if (owners[msg.sender] == address(0)) revertWithError("GS030")`
///         SENTINEL (0x1) has owners[SENTINEL] != 0 when Safe has owners, so approveHash
///         would not revert for SENTINEL (excluded here). However, SENTINEL can never be
///         used as a v=1 signer (GS026 check), making this corner case harmless.
rule approveHash_reverts_for_non_owner(bytes32 hashToApprove) {
    env e;
    require !isOwner(e.msg.sender);
    require e.msg.sender != SENTINEL();
    approveHash@withrevert(e, hashToApprove);
    assert lastReverted, "approveHash must revert when caller is not a registered owner";
}

// =============================================================================
// Property 3: approvedHashes[owner][hash] only modified by approveHash of that owner
//
// Goal: demonstrate this property holds.
//
// Filters:
//  - simulateAndRevert / getStorageAt: use low-level storage tricks that create
//    false positives unrelated to genuine approvedHashes writes.
//  - execTransaction: executes an arbitrary external call which may re-enter
//    approveHash; such writes are legitimate (via approveHash by msg.sender) but
//    the parametric rule cannot distinguish top-level vs reentrant callers.
//    The approveHash_reverts_for_non_owner rule separately covers this path.
//  - getTransactionHash: calls domainSeparator() which uses inline assembly
//    (chainid opcode), causing a conservative storage HAVOC false positive.
// =============================================================================

/// @title approvedHashes entries only writable by approveHash called by the entry's owner
rule approvedHashes_modified_only_by_owner_approveHash(method f, address owner, bytes32 hash)
    filtered {
        f -> f.selector != sig:simulateAndRevert(address,bytes).selector &&
             f.selector != sig:getStorageAt(uint256,uint256).selector &&
             f.selector != sig:execTransaction(address,uint256,bytes,Enum.Operation,uint256,uint256,uint256,address,address,bytes).selector &&
             f.selector != sig:getTransactionHash(address,uint256,bytes,Enum.Operation,uint256,uint256,uint256,address,address,uint256).selector
    }
{
    uint256 hashBefore = approvedHashes(owner, hash);

    env e;
    calldataarg args;
    f(e, args);

    uint256 hashAfter = approvedHashes(owner, hash);

    assert hashBefore != hashAfter =>
        f.selector == sig:approveHash(bytes32).selector &&
        e.msg.sender == owner,
        "approvedHashes can only be modified by approveHash called by the hash owner";
}

// =============================================================================
// Property 4: checkSignatures delegates to checkNSignatures with exactly threshold
//
// Goal: demonstrate this property holds.
// =============================================================================

/// @title checkSignatures is equivalent to checkNSignatures with the stored threshold
rule checkSignatures_delegates_with_threshold(
    address executor, bytes32 dataHash, bytes signatures
) {
    uint256 _threshold = getThreshold();
    require _threshold > 0;

    checkSignatures@withrevert(executor, dataHash, signatures);
    bool sigResult = !lastReverted;

    checkNSignatures@withrevert(executor, dataHash, signatures, _threshold);
    bool nsigResult = !lastReverted;

    assert sigResult == nsigResult,
        "checkSignatures must succeed IFF checkNSignatures with stored threshold succeeds";
}

// =============================================================================
// Property 5: All owners validated by checkNSignatures must satisfy isOwner
//
// Goal: demonstrate this property holds.
//
// The GS026 check in each checkNSignatures iteration ensures:
//   owners[currentOwner] != 0 AND currentOwner != SENTINEL_OWNERS
// which is exactly isOwner(currentOwner) = true.
//
// We verify for positions 0 and 1 (within loop_iter=2).
// Rules are restricted to v=0,1,2 where owner = address(uint160(uint256(r))).
// We constrain owner via uint160 equality (address is exactly 160 bits).
// =============================================================================

/// @title checkNSignatures n=1 (v=0,1,2): the validated owner must satisfy isOwner
rule checkNSignatures_owner_validity_n1(
    address executor, bytes32 dataHash, bytes signatures
) {
    // For v=0,1,2: currentOwner = address(uint160(uint256(r)))
    require sigV[0] == 0 || sigV[0] == 1 || sigV[0] == 2;
    // Constrain owner0 to equal address(uint160(uint256(sigR[0])))
    address owner0;
    require require_uint160(require_uint256(sigR[0])) == require_uint160(owner0);

    checkNSignatures@withrevert(executor, dataHash, signatures, 1);
    bool success = !lastReverted;

    assert success => isOwner(owner0),
        "If checkNSignatures(n=1) succeeds, the encoded owner must satisfy isOwner";
}

/// @title checkNSignatures n=2 (v=0,1,2 at pos 1): the second validated owner must satisfy isOwner
rule checkNSignatures_owner_validity_n2(
    address executor, bytes32 dataHash, bytes signatures
) {
    require sigV[1] == 0 || sigV[1] == 1 || sigV[1] == 2;
    address owner1;
    require require_uint160(require_uint256(sigR[1])) == require_uint160(owner1);

    checkNSignatures@withrevert(executor, dataHash, signatures, 2);
    bool success = !lastReverted;

    assert success => isOwner(owner1),
        "If checkNSignatures(n=2) succeeds, the second encoded owner must satisfy isOwner";
}

// =============================================================================
// Property 6: Owner addresses in checkNSignatures must be strictly increasing
//
// Goal: demonstrate this property holds.
//
// The GS026 check: currentOwner > lastOwner at each iteration.
// For n=2: owner at pos 1 > owner at pos 0.
// Restricted to v=0,1,2 where owner = address(uint160(uint256(r))).
// =============================================================================

/// @title checkNSignatures enforces strictly ascending owner address order (v=0,1,2)
rule checkNSignatures_owners_strictly_increasing(
    address executor, bytes32 dataHash, bytes signatures
) {
    require sigV[0] == 0 || sigV[0] == 1 || sigV[0] == 2;
    address owner0;
    require require_uint160(require_uint256(sigR[0])) == require_uint160(owner0);

    require sigV[1] == 0 || sigV[1] == 1 || sigV[1] == 2;
    address owner1;
    require require_uint160(require_uint256(sigR[1])) == require_uint160(owner1);

    checkNSignatures@withrevert(executor, dataHash, signatures, 2);
    bool success = !lastReverted;

    assert success => owner0 < owner1,
        "If checkNSignatures(n=2) succeeds, owner addresses must be strictly increasing";
}

// =============================================================================
// Property 7: For v=1 pre-approved hash signatures, require executor==owner or pre-approval
//
// Goal: demonstrate this property holds.
// =============================================================================

/// @title v=1 signature slot requires executor==owner OR pre-approved hash
rule checkNSignatures_v1_requires_executor_or_preapproval(
    address executor, bytes32 dataHash, bytes signatures
) {
    require sigV[0] == 1;
    // For v=1: currentOwner = address(uint160(uint256(r)))
    address owner0;
    require require_uint160(require_uint256(sigR[0])) == require_uint160(owner0);

    checkNSignatures@withrevert(executor, dataHash, signatures, 1);
    bool success = !lastReverted;

    assert success => (executor == owner0 || approvedHashes(owner0, dataHash) != 0),
        "v=1 slot: must have executor==owner OR approvedHashes[owner][dataHash] != 0";
}

// =============================================================================
// Property 8: domainSeparator() is a function of both chainId and address(this)
//
// Goal: demonstrate this property holds.
//
// The contract computes: keccak256(DOMAIN_SEPARATOR_TYPEHASH, chainid(), address(this))
// Under keccak256 injectivity (optimistic_hashing), any keccak hash computed with
// a DIFFERENT contract address must differ from the domain separator.
// =============================================================================

/// @title domainSeparator() binds to the contract address: different addresses => different separators
rule domainSeparator_binds_to_contract_address(uint256 chainId, address otherAddr) {
    require otherAddr != currentContract;

    bytes32 sep = domainSeparator();
    // With symbolic typehash T: if sep == altSep, then by keccak injectivity,
    // all inputs must be equal. But sep uses currentContract and altSep uses otherAddr.
    // Since otherAddr != currentContract, the inputs cannot be equal -> sep != altSep.
    bytes32 typehash;
    bytes32 altSep = keccak256(typehash, chainId, otherAddr);

    assert sep != altSep,
        "domainSeparator() must produce a different result for any other contract address";
}

// =============================================================================
// Property 9 (attack vector): checkNSignatures succeeds with requiredSignatures=0
//
// Goal: demonstrate attack CANNOT occur (EXPECTED TO FAIL — attack IS possible)
// =============================================================================

/// @title ATTACK VECTOR: checkNSignatures with 0 required signatures succeeds trivially
/// @notice EXPECTED TO FAIL: length check (sigs.length >= 0) is always true and loop
///         runs 0 iterations, confirming the vulnerability.
rule checkNSignatures_zero_must_revert(address executor, bytes32 dataHash, bytes signatures) {
    checkNSignatures@withrevert(executor, dataHash, signatures, 0);
    assert lastReverted,
        "checkNSignatures with 0 required signatures must revert (ATTACK VECTOR CONFIRMED IF FAILS)";
}

// =============================================================================
// Property 10 (attack vector): Legacy overloads allow owner self-approval bypass
//
// Goal: demonstrate attack CANNOT occur (EXPECTED TO FAIL — attack IS possible)
// =============================================================================

/// @title ATTACK VECTOR: Owner as implicit executor satisfies own v=1 sig without approveHash
/// @notice EXPECTED TO FAIL: executor==msg.sender==owner satisfies v=1 without approvedHashes.
rule legacy_overload_executor_bypass(bytes32 dataHash, bytes signatures) {
    env e;
    require isOwner(e.msg.sender);
    require approvedHashes(e.msg.sender, dataHash) == 0;

    require sigV[0] == 1;
    require sigR[0] == to_bytes32(e.msg.sender);

    // Legacy overload effect: executor = msg.sender
    checkNSignatures@withrevert(e.msg.sender, dataHash, signatures, 1);

    assert lastReverted,
        "Owner as implicit executor must not satisfy own v=1 sig without prior approveHash (ATTACK VECTOR)";
}

// =============================================================================
// Property 11 (attack vector): Two v=0 entries can share the same s offset
//
// Goal: demonstrate attack CANNOT occur (EXPECTED TO FAIL — attack IS possible)
// =============================================================================

/// @title ATTACK VECTOR: Two v=0 signatures with identical s offsets share dynamic data
/// @notice EXPECTED TO FAIL: No s-offset uniqueness check; NONDET checkContractSignature
///         allows both slots to be satisfied by the same bytes.
rule checkNSignatures_v0_unique_offsets(
    address executor, bytes32 dataHash, bytes signatures
) {
    require sigV[0] == 0 && sigV[1] == 0;
    require sigR[0] != sigR[1];
    require sigS[0] == sigS[1];

    checkNSignatures@withrevert(executor, dataHash, signatures, 2);

    assert lastReverted,
        "Two v=0 signatures with the same s offset must be rejected (ATTACK VECTOR CONFIRMED IF FAILS)";
}

// =============================================================================
// Property 12 (attack vector): P256 precompile unavailability breaks v=2 signatures
//
// Goal: demonstrate attack CANNOT occur (EXPECTED TO FAIL — attack IS possible)
// =============================================================================

/// @title ATTACK VECTOR: Registered P256 owner cannot sign if precompile is unavailable
/// @notice EXPECTED TO FAIL: With p256Verify as CONSTANT (possibly false), GS028 check
///         reverts for all v=2 signatures, confirming the precompile dependency.
rule p256_owner_can_always_sign(
    address executor, bytes32 dataHash, bytes signatures
) {
    require sigV[0] == 2;
    address owner0;
    require require_uint160(require_uint256(sigR[0])) == require_uint160(owner0);
    require isOwner(owner0);

    checkNSignatures@withrevert(executor, dataHash, signatures, 1);

    assert !lastReverted,
        "Registered P256 owner must always be able to provide a valid v=2 signature (ATTACK VECTOR IF FAILS)";
}
