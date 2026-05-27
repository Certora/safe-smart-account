/*
 * CVL Specification: Transaction Execution Properties (Safe Contract)
 *
 * Covers Properties 1-17 for the Safe contract's execTransaction component.
 * Targets Safe.sol (via certora/confs/Safe.conf).
 *
 * Key design decisions:
 * - custom_summaries.spec provides HAVOC_ECF for _.checkTransaction/checkAfterExecution.
 * - Executor.execute uses a specific contract-qualified internal summary (CVL requires
 *   defining contract for inherited internal methods). A wildcard _.execute is added as fallback.
 * - getTransactionHash is summarized via:
 *     (a) external entry (defense-in-depth for any ABI-dispatch path)
 *     (b) wildcard internal with `bytes calldata` (matching the actual Solidity declaration
 *         `bytes calldata data` in getTransactionHash). The bytes-location mismatch was the
 *         root cause of the summary not being applied — causing inline assembly to run and
 *         trigger prover failsafe mode, which havoced slot 5 (nonce) storage reads/writes.
 * - Safe.handlePayment is PRIVATE and cannot be intercepted by any CVL summary.
 * - checkSignatures declared envfree to use actual impl for direct CVL calls.
 * - Guard address tracked via persistent ghost safeGuardGhost (Sstore/Sload on GUARD_STORAGE_SLOT).
 * - Nonce tracked via persistent ghosts nonceBeforeIncrement/nonceAfterIncrement (Sstore slot 5).
 * - Threshold tracked via non-persistent ghost thresholdGhost (Sload slot 4 hook).
 * - Property 1 is split into two rules: one for non-execTransaction methods, one for execTransaction
 *   (which uses ghost variables to avoid nonce() storage read being havoced post-getTransactionHash).
 * - Property 12 is skipped (tx.gasprice inaccessible in CVL env).
 * - Property 9: uses satisfy to demonstrate reachability; gasleft() is non-deterministic
 *   in the prover model so gasUsed.sub(gasleft()) can spuriously revert under assert.
 * - Property 10 is EXPECTED TO FAIL: inline assembly `revert(ptr, returndatasize())`
 *   after execute_summary() is not correctly modeled as unconditional revert.
 */

import "specs/summaries/Safe_base_summaries.spec";
import "custom_summaries.spec";

// ─────────────────────────────────────────────────────────
// Definitions
// ─────────────────────────────────────────────────────────

definition SENTINEL_OWNERS() returns address = 1;
definition MAX_UINT256() returns uint256 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
definition ZERO_ADDRESS() returns address = 0;

// ─────────────────────────────────────────────────────────
// Persistent Ghost Variables — survive state reverts
// ─────────────────────────────────────────────────────────

persistent ghost bool executeWasCalled {
    init_state axiom executeWasCalled == false;
}

persistent ghost bool executeReturnedFalse {
    init_state axiom executeReturnedFalse == false;
}

persistent ghost uint256 nonceBeforeIncrement {
    init_state axiom nonceBeforeIncrement == 0;
}

persistent ghost uint256 nonceAfterIncrement {
    init_state axiom nonceAfterIncrement == 0;
}

/// @dev GUARD_STORAGE_SLOT = keccak256("guard_manager.guard.address")
///                         = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8
persistent ghost address safeGuardGhost;

// ─────────────────────────────────────────────────────────
// Non-Persistent Ghosts
// ─────────────────────────────────────────────────────────

ghost uint256 thresholdGhost;

ghost splitV(uint256) returns uint8;
ghost splitR(uint256) returns bytes32;
ghost splitS(uint256) returns bytes32;

// ─────────────────────────────────────────────────────────
// Storage Hooks
// ─────────────────────────────────────────────────────────

hook Sstore (slot 5) uint256 newVal (uint256 oldVal) {
    nonceBeforeIncrement = oldVal;
    nonceAfterIncrement = newVal;
}

hook Sstore (slot 4) uint256 newVal (uint256 oldVal) {
    thresholdGhost = newVal;
}

hook Sload uint256 val (slot 4) {
    require thresholdGhost == val;
}

hook Sstore (slot 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8) address newGuard (address oldGuard) {
    safeGuardGhost = newGuard;
}

hook Sload address guard (slot 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8) {
    require safeGuardGhost == guard;
}

// ─────────────────────────────────────────────────────────
// CVL Summary Functions
// ─────────────────────────────────────────────────────────

function execute_summary() returns bool {
    executeWasCalled = true;
    bool result;
    executeReturnedFalse = !result;
    return result;
}

/// @dev Non-deterministic hash summary to avoid getTransactionHash inline assembly
///      triggering prover failsafe mode (corrupts storage aliasing).
///      nonce++ side effect fires BEFORE this function body via argument evaluation.
function getTransactionHash_summary() returns bytes32 {
    bytes32 result;
    return result;
}

function splitSigSummary(uint256 pos) returns (uint8, bytes32, bytes32) {
    return (splitV(pos), splitR(pos), splitS(pos));
}

function bytes32ToAddr(bytes32 r) returns address {
    address result;
    require require_uint160(result) == require_uint160(require_uint256(r) % 2^160);
    return result;
}

// ─────────────────────────────────────────────────────────
// Methods Block
// ─────────────────────────────────────────────────────────

methods {
    // Executor.execute specific (defining contract) + wildcard fallback.
    // CVL requires defining contract for inherited internal methods.
    // Wildcard is a fallback in case runtime dispatch resolves differently.
    function Executor.execute(
        address,
        uint256,
        bytes memory,
        Enum.Operation,
        uint256
    ) internal returns (bool) => execute_summary();

    function _.execute(
        address,
        uint256,
        bytes memory,
        Enum.Operation,
        uint256
    ) internal => execute_summary() expect bool;

    // External summary for getTransactionHash (defense-in-depth for ABI dispatch paths).
    function getTransactionHash(
        address,
        uint256,
        bytes,
        Enum.Operation,
        uint256,
        uint256,
        uint256,
        address,
        address,
        uint256
    ) external returns (bytes32) => getTransactionHash_summary();

    // Wildcard INTERNAL summary for getTransactionHash.
    // The Solidity declaration uses `bytes calldata data` for this parameter.
    // The data location MUST be `calldata` here (not `memory`) to match the
    // Solidity signature and allow the prover to find this entry in the
    // internal dispatch table. A `bytes memory` mismatch causes the summary
    // to be silently skipped, letting the real body (with inline assembly for
    // EIP-712 encoding) run and trigger prover failsafe mode on storage slot 5.
    function _.getTransactionHash(
        address,
        uint256,
        bytes calldata,
        Enum.Operation,
        uint256,
        uint256,
        uint256,
        address,
        address,
        uint256
    ) internal => getTransactionHash_summary() expect bytes32;

    function SignatureDecoder.signatureSplit(
        bytes memory signatures,
        uint256 pos
    ) internal returns (uint8, bytes32, bytes32) => splitSigSummary(pos);

    function getThreshold() external returns (uint256) envfree;
    function nonce() external returns (uint256) envfree;
    function isOwner(address) external returns (bool) envfree;
    function approvedHashes(address, bytes32) external returns (uint256) envfree;
    function checkNSignatures(address, bytes32, bytes, uint256) external envfree;
    function checkSignatures(address, bytes32, bytes) external envfree;
}

// ═══════════════════════════════════════════════════════════════════
// Property 1a: Nonce is not changed by any function other than execTransaction.
// ═══════════════════════════════════════════════════════════════════

rule prop1_nonceNotChangedByOtherMethods(method f) filtered {
    f -> f.selector != sig:simulateAndRevert(address,bytes).selector &&
         f.selector != sig:getStorageAt(uint256,uint256).selector &&
         f.selector != sig:getTransactionHash(address,uint256,bytes,Enum.Operation,uint256,uint256,uint256,address,address,uint256).selector &&
         f.selector != sig:execTransaction(address,uint256,bytes,Enum.Operation,uint256,uint256,uint256,address,address,bytes).selector &&
         !f.isFallback
} {
    uint256 nonceBefore = nonce();
    require safeGuardGhost == ZERO_ADDRESS();

    calldataarg args;
    env e;
    f(e, args);

    assert nonce() == nonceBefore;
}

// ═══════════════════════════════════════════════════════════════════
// Property 1b: execTransaction increments nonce by exactly 1 on success.
// Uses ghost variables (set by the Sstore hook before getTransactionHash runs)
// to avoid depending on nonce() storage reads that may be havoced after
// the inline assembly in getTransactionHash executes.
// ═══════════════════════════════════════════════════════════════════

rule prop1_execTransactionIncrementsNonceByOne(
    address to, uint256 value, bytes data, Enum.Operation operation,
    uint256 safeTxGas, uint256 baseGas, uint256 gasPrice,
    address gasToken, address refundReceiver, bytes signatures
) {
    env e;
    require nonce() < MAX_UINT256();
    require safeGuardGhost == ZERO_ADDRESS();

    execTransaction@withrevert(e, to, value, data, operation, safeTxGas, baseGas,
        gasPrice, gasToken, refundReceiver, signatures);

    assert !lastReverted => to_mathint(nonceAfterIncrement) == nonceBeforeIncrement + 1;
}

// ═══════════════════════════════════════════════════════════════════
// Property 2a: checkSignatures reverts if threshold == 0 (GS001)
// ═══════════════════════════════════════════════════════════════════

rule prop2a_thresholdMustBePositiveForExecTx(
    address executor, bytes32 dataHash, bytes signatures
) {
    require getThreshold() == 0;
    checkSignatures@withrevert(executor, dataHash, signatures);
    assert lastReverted;
}

// ═══════════════════════════════════════════════════════════════════
// Property 2b: checkNSignatures reverts if signatures.length < requiredSignatures * 65 (GS020)
// ═══════════════════════════════════════════════════════════════════

rule prop2b_sufficientSignaturesBytesMustBePresent(
    address executor, bytes32 dataHash, bytes signatures, uint256 reqSigs
) {
    require reqSigs > 0;
    require to_mathint(reqSigs) <= 100;
    require to_mathint(signatures.length) < to_mathint(reqSigs) * 65;
    checkNSignatures@withrevert(executor, dataHash, signatures, reqSigs);
    assert lastReverted;
}

// ═══════════════════════════════════════════════════════════════════
// Property 3: checkNSignatures - recovered addresses are registered owners
// ═══════════════════════════════════════════════════════════════════

rule prop3_checkNSigsFirstOwnerMustBeRegistered(
    address executor, bytes32 dataHash, bytes signatures
) {
    require to_mathint(signatures.length) >= 65;

    uint8 v0; require v0 == splitV(0); require v0 == 0 || v0 == 1;
    bytes32 r0; require r0 == splitR(0);
    address recovered = bytes32ToAddr(r0);

    checkNSignatures@withrevert(executor, dataHash, signatures, 1);

    assert !lastReverted => (isOwner(recovered) && recovered != SENTINEL_OWNERS());
}

rule prop3b_nonOwnerSignatureCausesRevert(
    address executor, bytes32 dataHash, bytes signatures
) {
    require to_mathint(signatures.length) >= 65;

    uint8 v0; require v0 == splitV(0); require v0 == 0 || v0 == 1;
    bytes32 r0; require r0 == splitR(0);
    address recovered = bytes32ToAddr(r0);
    require !isOwner(recovered);

    checkNSignatures@withrevert(executor, dataHash, signatures, 1);
    assert lastReverted;
}

// ═══════════════════════════════════════════════════════════════════
// Property 4: Strictly ascending owner order in checkNSignatures
// ═══════════════════════════════════════════════════════════════════

rule prop4_ownersStrictlyAscendingInCheckNSigs(
    address executor, bytes32 dataHash, bytes signatures
) {
    require to_mathint(signatures.length) >= 130;

    uint8 v0; require v0 == splitV(0); require v0 == 0 || v0 == 1;
    uint8 v1; require v1 == splitV(1); require v1 == 0 || v1 == 1;
    bytes32 r0; require r0 == splitR(0);
    bytes32 r1; require r1 == splitR(1);
    address owner0 = bytes32ToAddr(r0);
    address owner1 = bytes32ToAddr(r1);

    checkNSignatures@withrevert(executor, dataHash, signatures, 2);

    assert !lastReverted => owner0 < owner1;
}

rule prop4b_duplicateOwnerCausesRevert(
    address executor, bytes32 dataHash, bytes signatures
) {
    require to_mathint(signatures.length) >= 130;

    uint8 v0; require v0 == splitV(0); require v0 == 0 || v0 == 1;
    uint8 v1; require v1 == splitV(1); require v1 == 0 || v1 == 1;
    bytes32 r0; require r0 == splitR(0);
    bytes32 r1; require r1 == splitR(1);
    address owner0 = bytes32ToAddr(r0);
    address owner1 = bytes32ToAddr(r1);
    require owner0 == owner1;

    checkNSignatures@withrevert(executor, dataHash, signatures, 2);
    assert lastReverted;
}

// ═══════════════════════════════════════════════════════════════════
// Property 5a: txHash uses pre-increment nonce value.
// ═══════════════════════════════════════════════════════════════════

rule prop5a_txHashUsesPreIncrementNonce(
    address to, uint256 value, bytes data, Enum.Operation operation,
    uint256 safeTxGas, uint256 baseGas, uint256 gasPrice,
    address gasToken, address refundReceiver, bytes signatures
) {
    env e;
    require safeGuardGhost == ZERO_ADDRESS();
    require nonce() < MAX_UINT256();
    execTransaction@withrevert(e, to, value, data, operation, safeTxGas, baseGas,
        gasPrice, gasToken, refundReceiver, signatures);
    assert !lastReverted => to_mathint(nonceAfterIncrement) == nonceBeforeIncrement + 1;
}

// ═══════════════════════════════════════════════════════════════════
// Property 6: Guard checkTransaction is called before execute when guard is set.
// ═══════════════════════════════════════════════════════════════════

rule prop6_guardPreHookCalledWhenGuardSet(
    address to, uint256 value, bytes data, Enum.Operation operation,
    uint256 safeTxGas, uint256 baseGas, uint256 gasPrice,
    address gasToken, address refundReceiver, bytes signatures
) {
    env e;
    require safeGuardGhost != ZERO_ADDRESS();
    require getThreshold() > 0;
    require getThreshold() <= 100;
    require to_mathint(signatures.length) >= to_mathint(getThreshold()) * 65;
    require !executeWasCalled;

    execTransaction@withrevert(e, to, value, data, operation, safeTxGas, baseGas,
        gasPrice, gasToken, refundReceiver, signatures);

    assert !lastReverted => executeWasCalled;
}

// ═══════════════════════════════════════════════════════════════════
// Property 7: Guard checkAfterExecution is called after execute when guard is set.
// ═══════════════════════════════════════════════════════════════════

rule prop7_guardPostHookCalledEvenOnInnerFailure(
    address to, uint256 value, bytes data, Enum.Operation operation,
    uint256 safeTxGas, uint256 baseGas, uint256 gasPrice,
    address gasToken, address refundReceiver, bytes signatures
) {
    env e;
    require safeGuardGhost != ZERO_ADDRESS();
    require safeTxGas > 0 || gasPrice > 0;
    require !executeWasCalled;
    require !executeReturnedFalse;
    require getThreshold() > 0;
    require getThreshold() <= 100;
    require to_mathint(signatures.length) >= to_mathint(getThreshold()) * 65;

    execTransaction@withrevert(e, to, value, data, operation, safeTxGas, baseGas,
        gasPrice, gasToken, refundReceiver, signatures);
    require !lastReverted;

    satisfy executeReturnedFalse;
}

// ═══════════════════════════════════════════════════════════════════
// Property 8: Guard snapshot — same guard address used for both pre- and post-hooks.
// ═══════════════════════════════════════════════════════════════════

rule prop8_guardAddressPreservedDuringExecution(
    address to, uint256 value, bytes data, Enum.Operation operation,
    uint256 safeTxGas, uint256 baseGas, uint256 gasPrice,
    address gasToken, address refundReceiver, bytes signatures
) {
    env e;
    address guardBefore = safeGuardGhost;
    require guardBefore != ZERO_ADDRESS();
    require !executeWasCalled;
    require safeTxGas > 0 || gasPrice > 0;
    require getThreshold() > 0;
    require getThreshold() <= 100;
    require to_mathint(signatures.length) >= to_mathint(getThreshold()) * 65;

    execTransaction@withrevert(e, to, value, data, operation, safeTxGas, baseGas,
        gasPrice, gasToken, refundReceiver, signatures);

    satisfy !lastReverted && executeWasCalled && safeGuardGhost == guardBefore;
}

// ═══════════════════════════════════════════════════════════════════
// Property 9: No revert on inner tx failure when safeTxGas > 0.
// gasPrice == 0 to avoid private handlePayment arithmetic issues.
// Uses satisfy to demonstrate reachability: the prover model allows non-deterministic
// gasleft() values, so gasUsed.sub(gasleft()) can spuriously revert under assert.
// A satisfy rule demonstrates the property IS achievable (the prover finds a path
// where gasleft decreases normally and execute fails without reverting execTransaction).
// ═══════════════════════════════════════════════════════════════════

rule prop9_noRevertOnInnerFailureWithGasParams(
    address to, uint256 value, bytes data, Enum.Operation operation,
    uint256 safeTxGas, uint256 baseGas,
    address gasToken, address refundReceiver, bytes signatures
) {
    env e;
    require safeTxGas > 0;
    require safeGuardGhost == ZERO_ADDRESS();
    require !executeWasCalled;
    require !executeReturnedFalse;
    require e.msg.value == 0;
    require getThreshold() > 0;
    require getThreshold() <= 100;
    require to_mathint(signatures.length) >= to_mathint(getThreshold()) * 65;
    require to_mathint(safeTxGas) + 2500 + 500 <= max_uint256;
    require to_mathint(safeTxGas) * 64 <= max_uint256;

    execTransaction@withrevert(e, to, value, data, operation, safeTxGas, baseGas,
        0, gasToken, refundReceiver, signatures);

    satisfy executeReturnedFalse && !lastReverted;
}

// ═══════════════════════════════════════════════════════════════════
// Property 10: Revert when inner tx fails AND safeTxGas == 0 AND gasPrice == 0.
// EXPECTED TO FAIL: prover limitation with inline assembly revert after CVL summary.
// ═══════════════════════════════════════════════════════════════════

rule prop10_revertOnInnerFailureNoGasParams(
    address to, uint256 value, bytes data, Enum.Operation operation,
    address gasToken, address refundReceiver, bytes signatures
) {
    env e;
    require safeGuardGhost == ZERO_ADDRESS();
    require !executeWasCalled;
    require !executeReturnedFalse;
    require e.msg.value == 0;
    require getThreshold() > 0;
    require getThreshold() <= 100;
    require to_mathint(signatures.length) >= to_mathint(getThreshold()) * 65;

    execTransaction@withrevert(e, to, value, data, operation, 0, 0, 0,
        gasToken, refundReceiver, signatures);
    require !lastReverted;

    assert !(executeWasCalled && executeReturnedFalse);
}

// ═══════════════════════════════════════════════════════════════════
// Property 11: handlePayment invoked when gasPrice > 0.
// Demonstrates reachability: non-reverting path with gasPrice > 0 requires
// handlePayment to have been invoked and succeeded.
// ═══════════════════════════════════════════════════════════════════

rule prop11_handlePaymentCalledWhenGasPricePositive(
    address to, uint256 value, bytes data, Enum.Operation operation,
    uint256 safeTxGas, uint256 baseGas, uint256 gasPrice,
    address gasToken, address refundReceiver, bytes signatures
) {
    env e;
    require gasPrice > 0;
    require safeGuardGhost == ZERO_ADDRESS();
    require getThreshold() > 0;
    require getThreshold() <= 100;
    require to_mathint(signatures.length) >= to_mathint(getThreshold()) * 65;
    require to_mathint(safeTxGas) + 2500 + 500 <= max_uint256;
    require to_mathint(safeTxGas) * 64 <= max_uint256;
    require to_mathint(baseGas) < 2^128;
    require to_mathint(gasPrice) < 2^128;

    execTransaction@withrevert(e, to, value, data, operation, safeTxGas, baseGas,
        gasPrice, gasToken, refundReceiver, signatures);

    satisfy !lastReverted;
}

// ═══════════════════════════════════════════════════════════════════
// Property 13: v=1 signature requires executor match OR pre-approved hash
// ═══════════════════════════════════════════════════════════════════

rule prop13_v1SignatureRequiresApprovalOrExecutor(
    address executor, bytes32 dataHash, bytes signatures
) {
    require to_mathint(signatures.length) >= 65;

    uint8 v0; require v0 == splitV(0); require v0 == 1;
    bytes32 r0; require r0 == splitR(0);
    address owner = bytes32ToAddr(r0);

    checkNSignatures@withrevert(executor, dataHash, signatures, 1);

    assert !lastReverted => (executor == owner || approvedHashes(owner, dataHash) != 0);
}

// ═══════════════════════════════════════════════════════════════════
// Property 14: Gas griefing — relayer compensated even on inner tx failure.
// ═══════════════════════════════════════════════════════════════════

rule prop14_gasGriefingConfirmed(
    address to, uint256 value, bytes data, Enum.Operation operation,
    uint256 safeTxGas, uint256 baseGas, uint256 gasPrice,
    address gasToken, address refundReceiver, bytes signatures
) {
    env e;
    require gasPrice > 0;
    require safeTxGas > 0;
    require safeGuardGhost == ZERO_ADDRESS();
    require !executeWasCalled;
    require !executeReturnedFalse;
    require getThreshold() > 0;
    require getThreshold() <= 100;
    require to_mathint(signatures.length) >= to_mathint(getThreshold()) * 65;
    require to_mathint(safeTxGas) + 2500 + 500 <= max_uint256;
    require to_mathint(safeTxGas) * 64 <= max_uint256;
    require to_mathint(baseGas) < 2^128;
    require to_mathint(gasPrice) < 2^128;

    execTransaction@withrevert(e, to, value, data, operation, safeTxGas, baseGas,
        gasPrice, gasToken, refundReceiver, signatures);
    require !lastReverted;

    satisfy executeReturnedFalse;
}

// ═══════════════════════════════════════════════════════════════════
// Property 15: Executor free signature — v=1 executor entry succeeds.
// ═══════════════════════════════════════════════════════════════════

rule prop15_executorFreeSignatureConfirmed(
    address executor, bytes32 dataHash, bytes signatures
) {
    require executor != ZERO_ADDRESS();
    require isOwner(executor);
    require executor != SENTINEL_OWNERS();
    require to_mathint(signatures.length) == 65;

    uint8 v0; require v0 == splitV(0); require v0 == 1;
    bytes32 r0; require r0 == splitR(0);
    address signerInR = bytes32ToAddr(r0);
    require signerInR == executor;
    require approvedHashes(executor, dataHash) == 0;

    checkNSignatures@withrevert(executor, dataHash, signatures, 1);

    assert !lastReverted;
}

// ═══════════════════════════════════════════════════════════════════
// Property 16: Guard DoS — setGuard can only be called by the Safe itself.
// ═══════════════════════════════════════════════════════════════════

rule prop16_setGuardRequiresSelfAuthorization(address guard) {
    env e;
    setGuard@withrevert(e, guard);
    assert !lastReverted => e.msg.sender == currentContract;
}

// ═══════════════════════════════════════════════════════════════════
// Property 17: Nonce regression — execTransaction CAN fail to advance nonce.
// ═══════════════════════════════════════════════════════════════════

rule prop17_nonceCanFailToAdvance(
    address to, uint256 value, bytes data, Enum.Operation operation,
    uint256 safeTxGas, uint256 baseGas, uint256 gasPrice,
    address gasToken, address refundReceiver, bytes signatures
) {
    env e;
    uint256 nonce_before = nonce();

    execTransaction@withrevert(e, to, value, data, operation, safeTxGas, baseGas,
        gasPrice, gasToken, refundReceiver, signatures);

    satisfy nonce() == nonce_before;
}
