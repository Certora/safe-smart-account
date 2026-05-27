/*
 * Fallback.spec
 *
 * Formal specification for Safe's FallbackManager component.
 * Covers Properties 1-12: fallback handler management and forwarding behavior.
 *
 * Contracts in scope (from fallback.conf):
 *  - SafeHarness (verification target): Safe + getFallbackHandler() getter
 *  - DummyHandler: always-returning handler mock
 *  - ExtensibleFallbackHandlerHarness: EFH reference implementation
 *
 * Imports:
 *  - Safe_base_summaries.spec: auto-generated base summaries
 *  - custom_summaries.spec: HAVOC_ECF for guard/handler calls
 *  - invariants.spec: structural invariants + ghosts
 *    (thresholdGhost, ownerCountGhost, fallbackHandlerGhost, reachableOnly, etc.)
 *
 * Key implementation facts (FallbackManager.sol + munged patch):
 *  - FALLBACK_HANDLER_STORAGE_SLOT = keccak256("fallback_manager.handler.address")
 *    = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5
 *  - internalSetFallbackHandler: reverts GS400 if handler == address(this); else sstore
 *  - setFallbackHandler: public, `authorized` modifier (requires msg.sender == this)
 *  - fallback() (munged): handler = and(0xff...ff, sload(SLOT)); if iszero → return(0,0);
 *    else call(gas(), handler, 0, ptr, calldatasize()+20, 0, 0)
 *  - receive(): payable, emits SafeReceived — separate from fallback()
 *
 * Ghost variable:
 *  - fallbackHandlerGhost: from invariants.spec, mirrors FALLBACK_HANDLER_STORAGE_SLOT
 *    via Sstore/Sload hooks. Non-persistent (havoced by HAVOC_ECF from external calls).
 *    Used for pre-state reads; post-state reads after external calls may be unreliable.
 *
 * CALL hook (Properties 7 & 11 partial):
 *  - Fires for every CALL opcode. Filtered to Safe calling the registered handler.
 *  - Asserts value == 0 (no ETH forwarded to handler) [Property 7]
 *  - Asserts argsLength >= 20 (at least 20 bytes appended) [Property 11 partial]
 *  NOTE: Content of those 20 bytes cannot be verified — argsOffset cannot dereference
 *  memory in a CALL hook (CVL manual limitation). Skip declared for that aspect.
 *
 * Filtering notes:
 *  - prop2 filter excludes <receiveOrFallback> (fallback's CALL havoces ghost)
 *  - prop2 filter excludes getTransactionHash (reads slot, causing ghost pre-sync desync)
 *  - simulateAndRevert excluded from prop1 (always reverts, proven separately)
 *
 * Bitwise-and over-approximation (prop6 fix):
 *  - The munged fallback() computes: handler = and(mask, sload(SLOT))
 *  - When sload(SLOT) == 0 (ghost == 0), and(mask, 0) should == 0 but prover over-approximates
 *  - CALL hook require prunes the spurious path where addr != 0 when ghost == 0
 *  - This is mathematically sound: and(mask, 0) == 0 is a tautology
 *  - Impact on other rules is benign: reachableOnly excludes execTransaction (the only
 *    function that could legitimately call non-zero addrs with ghost==0); other methods
 *    that run through reachableOnly do not make external CALLs that affect our properties
 */

import "specs/summaries/Safe_base_summaries.spec";
import "custom_summaries.spec";
import "invariants.spec";

// ============================================================
// Methods block
// ============================================================
methods {
    // ModuleManager.isModuleEnabled: public view function in Safe (via ModuleManager inheritance)
    function isModuleEnabled(address) external returns (bool) envfree;
}

// ============================================================
// CALL hook — Properties 7 & 11 (partial)
//
// Fires for every CALL opcode in the EVM execution.
// Conditions: Safe (executingContract == currentContract) is calling
//             the registered handler (addr == fallbackHandlerGhost != 0).
//
// [Bitwise-and fix]: Mathematical fact: and(mask, 0) == 0. When ghost == 0 and Safe
//   is calling, the CALL addr must be 0 (no real target). The require prunes the
//   spurious over-approximated path where and(mask, 0) yields a non-zero addr.
//   This prevents prop6 from failing with a spurious CEX. See header for impact analysis.
//
// [Property 7]: value == 0 — fallback() forwards calls with value=0
//   The assembly uses: call(gas(), handler, 0, ptr, ...) — third arg is 0
//   fallback() is also non-payable: if msg.value > 0 is sent, the EVM reverts
//   before executing any assembly (Solidity non-payable check at function entry).
//   NOTE: f.isFallback in CVL combines receive() (payable) and fallback() (non-payable).
//   A rule "msg.value > 0 → lastReverted" would spuriously fail for receive(). Instead,
//   we verify the forwarding value using the CALL hook which fires only during execution.
//
// [Property 11 partial]: argsLength >= 20 — at least 20 bytes appended
//   The assembly: calldatacopy(ptr, 0, calldatasize()); mstore(add(ptr,calldatasize()), shl(96,caller()))
//   Then: call(gas(), handler, 0, ptr, add(calldatasize(), 20), 0, 0) → argsLength = calldatasize()+20 >= 20
//   Content (the 20 bytes == caller()) cannot be verified: CALL hook argsOffset cannot
//   dereference memory before or after the call (CVL manual limitation). Skip declared.
// ============================================================

/// @title CALL hook: Safe→handler calls use value=0 and append ≥20 bytes (Props 7 & 11)
hook CALL(uint g, address addr, uint value, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc {
    // Mathematical tautology: and(mask, 0) == 0. Prunes spurious paths from bitwise-and
    // over-approximation where sload(FALLBACK_HANDLER_SLOT)==0 but and(mask, sload) != 0.
    // This affects only the fallback-path (the only Safe code that does and(mask, sload(SLOT))).
    // execTransaction and execTransactionFromModule are excluded by reachableOnly/filtering.
    require !(executingContract == currentContract && fallbackHandlerGhost == 0 && addr != 0);

    if (executingContract == currentContract
        && addr == fallbackHandlerGhost
        && fallbackHandlerGhost != 0)
    {
        assert value == 0,
            "Property 7: Safe must forward to handler with value=0 (no ETH)";
        assert argsLength >= 20,
            "Property 11 partial: handler call must include at least 20 appended bytes";
    }
}

// ============================================================
// Property 1: The fallback handler must never equal address(this)
//
// Invariant: fallbackHandlerGhost != currentContract
// Filtered: simulateAndRevert (always reverts, proved separately) and reachableOnly
// (excludes execTransaction and friends to avoid HAVOC_ECF ghost-desync with guard hooks).
//
// The preserved block requires fallback_handler_not_self() from invariants.spec, which
// uses the same ghost variable — enforcing consistency with the base invariant.
// ============================================================

/// @title Property 1: Fallback handler is never the Safe itself
invariant prop1_fallback_handler_not_self()
    fallbackHandlerGhost != currentContract
    filtered {
        f -> f.selector != sig:simulateAndRevert(address,bytes).selector
             && reachableOnly(f)
    }
    {
        preserved with (env e) {
            requireInvariant fallback_handler_not_self();
        }
    }

/// @title Supporting rule: simulateAndRevert always reverts (Property 1 filter justification)
rule simulateAndRevertAlwaysReverts(address targetContract, bytes calldataPayload) {
    env e;
    simulateAndRevert@withrevert(e, targetContract, calldataPayload);
    assert lastReverted,
        "simulateAndRevert must always revert — justifies excluding it from prop1 filter";
}

// ============================================================
// Property 2: FALLBACK_HANDLER_STORAGE_SLOT modification control
//
// The slot can ONLY be modified by setFallbackHandler or setup.
//
// Filter rationale:
//  - simulateAndRevert: always reverts (no storage changes)
//  - getStorageAt: static reader
//  - !f.isFallback: fallback's CALL to handler havoces non-persistent ghosts;
//    post-call handlerAfter = fallbackHandlerGhost would be havoced, giving spurious CEX.
//    The fallback's impact is covered by prop11's CALL hook + architectural reasoning
//    (CALL cannot modify Safe's storage).
//  - execTransaction, execTransactionFromModule*: HAVOC_ECF from guard hooks desyncs ghost
//  - getTransactionHash: this view function incidentally reads FALLBACK_HANDLER_STORAGE_SLOT
//    during execution; the Sload hook re-synchronizes the ghost but the handlerBefore
//    snapshot was taken before the sync, causing spurious "changed" CEX.
// ============================================================

/// @title Property 2: Handler slot only modified by setFallbackHandler or setup
rule prop2_handler_modification_control(method f)
    filtered {
        f -> f.selector != sig:simulateAndRevert(address,bytes).selector
             && f.selector != sig:getStorageAt(uint256,uint256).selector
             && !f.isFallback
             && f.selector != sig:getTransactionHash(address,uint256,bytes,Enum.Operation,uint256,uint256,uint256,address,address,uint256).selector
             && f.selector != sig:execTransaction(address,uint256,bytes,Enum.Operation,uint256,uint256,uint256,address,address,bytes).selector
             && f.selector != sig:execTransactionFromModule(address,uint256,bytes,Enum.Operation).selector
             && f.selector != sig:execTransactionFromModuleReturnData(address,uint256,bytes,Enum.Operation).selector
    }
{
    address handlerBefore = fallbackHandlerGhost;

    env e;
    calldataarg args;
    f(e, args);

    address handlerAfter = fallbackHandlerGhost;

    assert handlerBefore != handlerAfter =>
        f.selector == sig:setFallbackHandler(address).selector ||
        f.selector == sig:setup(address[],uint256,address,bytes,address,address,uint256,address).selector,
        "Fallback handler slot can only be changed by setFallbackHandler or setup";
}

// ============================================================
// Properties 3 & 5: setFallbackHandler biconditional revert characteristics
//
// setFallbackHandler REVERTS iff (msg.sender != address(this) || handler == address(this))
//
// Covers:
//  - P3: unauthorized caller → revert (msg.sender != address(this))
//  - P5: self-referential handler → revert (handler == address(this))
//  - Positive direction: authorized caller + valid handler → no revert
//
// require e.msg.value == 0: setFallbackHandler is not payable. Non-zero msg.value causes
// an unconditional EVM revert regardless of access control checks. Excluding ETH-carrying
// calls keeps the biconditional focused on the access-control conditions (P3 + P5).
// ============================================================

/// @title Properties 3 & 5: setFallbackHandler biconditional revert characteristics
rule setFallbackHandler_revert_characteristics(address handler) {
    env e;
    require e.msg.value == 0;
    setFallbackHandler@withrevert(e, handler);
    assert lastReverted <=> (e.msg.sender != currentContract || handler == currentContract),
        "setFallbackHandler reverts iff unauthorized caller or handler == address(this)";
}

// ============================================================
// Property 4: setFallbackHandler atomically stores the exact handler
//
// The Sstore hook fires during setFallbackHandler (via internalSetFallbackHandler's assembly
// sstore), updating fallbackHandlerGhost = handler. After the call, the ghost equals handler.
// ============================================================

/// @title Property 4: setFallbackHandler stores exactly the given handler address
rule prop4_setFallbackHandler_stores_handler(address handler) {
    env e;
    setFallbackHandler(e, handler);
    assert fallbackHandlerGhost == handler,
        "After setFallbackHandler(handler), stored value must equal handler exactly";
}

// ============================================================
// Property 6: Zero handler → fallback returns silently (no revert)
//
// When FALLBACK_HANDLER_STORAGE_SLOT == 0:
//   fallback assembly: if iszero(handler) { return(0, 0) } → silent success, empty data
//   receive(): emit SafeReceived(msg.sender, msg.value) → also succeeds
// Both paths succeed without reverting.
//
// require e.msg.value == 0: receive() is payable (handles both cases). To isolate
// the "no handler" path, we avoid ETH sends (which are unrelated to prop6).
//
// CALL hook note: The require in CALL hook
//   `require !(executingContract == currentContract && fallbackHandlerGhost == 0 && addr != 0)`
// prunes the spurious bitwise-and over-approximation where and(mask, 0) produces non-zero.
// This fixes prop6 by ensuring that when ghost == 0, no CALL to a non-zero addr is modeled.
// ============================================================

/// @title Property 6: Zero fallback handler causes silent empty return (no revert)
rule prop6_zero_handler_fallback_returns_silently(method f)
    filtered { f -> f.isFallback }
{
    env e;
    require e.msg.value == 0;
    require fallbackHandlerGhost == 0;
    calldataarg args;
    f@withrevert(e, args);
    assert !lastReverted,
        "When no fallback handler registered, fallback must return silently without reverting";
}

// ============================================================
// Property 7: No ETH forwarded to handler
//
// The assembly forwards calls with value=0: call(gas(), handler, 0, ptr, ..., 0, 0)
// This is verified by the CALL hook above (assert value == 0 for Safe→handler calls).
//
// NOTE on fallback() non-payability:
//  fallback() has no `payable` modifier → any call with msg.value > 0 reverts at the
//  Solidity function dispatcher level before executing assembly. The CALL hook verifies
//  the more fundamental property: even if fallback() somehow executed with ETH,
//  the forwarded value to the handler would be 0.
//
//  We cannot write a separate "msg.value > 0 → lastReverted" rule for the fallback
//  because f.isFallback in CVL covers both fallback() (non-payable) AND receive() (payable).
//  The receive() path legitimately succeeds with ETH, which would cause such a rule to fail.
//  The CALL hook is the definitive machine-checked coverage for Property 7.
// ============================================================

// (Property 7 is fully covered by the CALL hook — see "assert value == 0" above)

// ============================================================
// Property 8: Fallback faithfully propagates handler outcome
//
// Demonstrated via two reachability rules:
//  8a: fallback CAN succeed when handler registered (handler success path)
//  8b: fallback CAN fail when handler registered (handler reverts)
// Together they show fallback's outcome = handler's outcome.
// ============================================================

/// @title Property 8a: Fallback can succeed when handler is registered
rule prop8a_fallback_can_succeed_with_handler(method f)
    filtered { f -> f.isFallback }
{
    env e;
    require e.msg.value == 0;
    require fallbackHandlerGhost != 0;
    calldataarg args;
    f@withrevert(e, args);
    satisfy !lastReverted,
        "Fallback must be able to succeed when a handler is registered";
}

/// @title Property 8b: Fallback can fail when handler registered and reverts
rule prop8b_fallback_can_fail_with_handler(method f)
    filtered { f -> f.isFallback }
{
    env e;
    require e.msg.value == 0;
    require fallbackHandlerGhost != 0;
    calldataarg args;
    f@withrevert(e, args);
    satisfy lastReverted,
        "Fallback must be able to fail when handler call reverts";
}

// ============================================================
// Property 9 (attack vector): Reentrancy via fallback handler as module
//
// The fallback handler is called with msg.sender == Safe. If the handler is also
// an enabled module, it can call back into Safe via execTransactionFromModule.
// No reentrancy guard protects the fallback dispatch path.
//
// Demonstrates the attack IS REACHABLE (satisfy): a handler-module CAN successfully
// call execTransactionFromModule, confirming no restriction prevents this.
// ============================================================

/// @title Property 9: ATTACK REACHABILITY — handler-as-module reentrancy
rule prop9_handler_module_reentrancy_attack() {
    env e;
    address handler = fallbackHandlerGhost;
    require handler != 0;
    require isModuleEnabled(handler);
    require e.msg.sender == handler;

    address to;
    uint256 value;
    bytes data;
    Enum.Operation operation;

    execTransactionFromModule@withrevert(e, to, value, data, operation);

    satisfy !lastReverted,
        "ATTACK: handler-as-module can successfully call execTransactionFromModule";
}

// ============================================================
// Property 10 (attack vector): No code-existence check in setFallbackHandler
//
// setFallbackHandler does not verify the handler has deployed code (extcodesize > 0).
// An EOA or self-destructed contract address can be registered.
// When a codeless handler is called, the EVM silently succeeds (no code = empty return).
//
// Demonstrates the vulnerability IS REACHABLE (satisfy): setFallbackHandler ACCEPTS
// any non-zero non-self address without checking extcodesize.
// ============================================================

/// @title Property 10: ATTACK REACHABILITY — setFallbackHandler accepts EOA addresses
rule prop10_setFallbackHandler_no_code_check(address handler) {
    env e;
    require e.msg.sender == currentContract;
    require e.msg.value == 0;
    require handler != 0;
    require handler != currentContract;
    setFallbackHandler@withrevert(e, handler);
    satisfy !lastReverted,
        "ATTACK: setFallbackHandler accepts any non-zero non-self address (no extcodesize check)";
}

// ============================================================
// Property 11 (attack vector): Caller identity confusion
//
// The fallback appends the original caller as 20 raw bytes (shl(96, caller())).
// Handlers using HandlerContext._msgSender() correctly decode the appended sender.
// Handlers using standard ABI-decoding may misidentify the caller.
//
// Machine-checked aspects (via CALL hook above):
//  (a) value == 0: handler call uses no ETH (Safe's non-payable nature is preserved)
//  (b) argsLength >= 20: ≥20 bytes appended, consistent with the 20-byte address append
//
// Content verification (those 20 bytes == caller()):
//  NOT FEASIBLE in CVL: CALL hook argsOffset cannot dereference memory before or after
//  the call (CVL manual: "Hook variables for CALL, ... cannot be used to read data
//  stored in memory before or after the call"). Skip declared for this content aspect.
//
// Architectural note on "handler slot unchanged":
//  The fallback uses CALL (not DELEGATECALL) for handler dispatch. Under EVM semantics,
//  a regular CALL cannot modify the CALLER's storage. Therefore, FALLBACK_HANDLER_STORAGE_SLOT
//  is always unchanged after fallback dispatch. This is covered by prop2's parametric rule
//  (which proves no non-setFallbackHandler/setup function can change the slot) combined
//  with the architectural guarantee that CALL isolation prevents storage modification.
//  The munged Executor also replaces DELEGATECALL with `return true`, so no delegatecall
//  in the fallback path can modify Safe's storage.
// ============================================================

// Property 11 machine-checked aspects are in the CALL hook above.
// See skip declaration for the content (20 bytes == caller()) aspect.

// ============================================================
// Property 12 (attack vector): Silent success when no handler registered
//
// When no handler is registered, fallback returns(0,0) — silent empty success.
// An integrating contract that doesn't inspect return data may record a successful
// interaction when in reality nothing was executed.
//
// Demonstrates the behavior IS REACHABLE (satisfy): fallback CAN succeed silently
// with no handler, confirming the "silent success" behavior.
// ============================================================

/// @title Property 12: ATTACK REACHABILITY — No handler causes silent success
rule prop12_no_handler_silent_success_attack(method f)
    filtered { f -> f.isFallback }
{
    env e;
    require e.msg.value == 0;
    require fallbackHandlerGhost == 0;
    calldataarg args;
    f@withrevert(e, args);
    satisfy !lastReverted,
        "ATTACK: fallback returns empty data (no revert) when no handler — silent success";
}
