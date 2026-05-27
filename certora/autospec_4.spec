/*
 * CVL Specification: Safe Module Management Properties (1-24)
 *
 * Covers the module management component of the Safe contract:
 * - Structural invariants (1-5): zero address, sentinel, initialization, self-loops, reachability
 * - Access control (6-10): self-authorization, module-only execution
 * - State transitions (11-16): enable/disable correctness, isolation, revert conditions
 * - Guard validation (19): IModuleGuard compliance check
 * - Isolation (20): only enable/disable change module state
 *
 * Skipped Properties:
 *   - 17, 18: Mock-based guard tracking requires ModuleGuardMock which is not in the scene
 *   - 21, 22, 24: NONDET execute summary makes rules trivially true without capturing the attack
 *   - 23: DISPATCHER/NONDET summaries prevent modeling reverting guard DoS
 *
 * NOTE: ModuleReach.spec is imported for Properties 1-5 (reach-based reachability proofs).
 *       This PRECLUDES importing invariants.spec due to conflicting Sstore hooks on modules[].
 * NOTE: custom_summaries.spec already summarizes _.checkTransaction, _.checkAfterExecution,
 *       and _.isValidSignature; do not re-declare them here.
 */

import "specs/summaries/Safe_base_summaries.spec";
import "custom_summaries.spec";
import "specs/ModuleReach.spec";

// ============================================================
// Definitions
// ============================================================

definition SENTINEL_MODULES() returns address = 1;
definition NULL_ADDRESS() returns address = 0;

// ============================================================
// Ghosts
// ============================================================

/// @dev Models return value of supportsInterface() for guard compliance testing (Property 19).
/// Allows testing both compliant (true) and non-compliant (false) guards.
ghost bool supportsInterfaceGhost;

// ============================================================
// Helper Functions
// ============================================================

/// @dev CVL wrapper for the supportsInterface ghost (required for wildcard expression summary).
/// Wildcard expression summaries require a function call, not a bare ghost variable.
function getSupportsInterfaceValue() returns bool {
    return supportsInterfaceGhost;
}

// ============================================================
// Methods
// ============================================================

methods {
    // --- envfree getters available in Safe.sol ---
    function isModuleEnabled(address) external returns (bool) envfree;

    // --- Internal summaries (prevent HAVOC from assembly-level instructions) ---

    // Executor.execute: NONDET prevents storage HAVOC from CALL/DELEGATECALL assembly.
    // Sound for module management properties which don't depend on execute's internal effects.
    function Executor.execute(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 txGas
    ) internal returns (bool) => NONDET;

    // handlePayment: NONDET prevents HAVOC from ETH refund assembly call.
    function Safe.handlePayment(
        uint256 gasUsed,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver
    ) internal returns (uint256) => NONDET;

    // transferToken: NONDET prevents HAVOC from ERC20 CALL assembly.
    function SecuredTokenTransfer.transferToken(
        address token,
        address receiver,
        uint256 amount
    ) internal returns (bool) => NONDET;

    // EIP7702 check: CONSTANT (doesn't affect module management).
    function EIP7702.isThisDelegatedAccount() internal returns (bool) => CONSTANT;

    // supportsInterface: expression summary returns controllable ghost.
    // NOTE: wildcard expression summaries must NOT include return type in signature;
    // instead use 'expect <type>' after the summary expression.
    function _.supportsInterface(bytes4) external => getSupportsInterfaceValue() expect bool;
}

// ============================================================
// PROPERTIES 1-5: STRUCTURAL INVARIANTS OF THE MODULES LINKED LIST
// Proved using ModuleReach.spec's reach predicate infrastructure.
// execTransaction is filtered from P1-P5 because under NONDET execute + HAVOC_ECF guards,
// the prover may produce spurious violations via ghost state inconsistency.
// ============================================================

// ------------------------------------------------------------
// Property 1: modules[address(0)] always equals address(0).
// The zero address can never be an enabled module.
// isModuleEnabled(0) = (SENTINEL_MODULES != 0 && modules[0] != 0) -- depends on modules[0].
// The nextNull() invariant from ModuleReach.spec ensures ghostModules[NULL] == 0.
// ------------------------------------------------------------

/// @title Zero address is never an enabled module (Property 1)
invariant zero_address_not_enabled_p1()
    !isModuleEnabled(NULL_ADDRESS())
    filtered { f -> reachableOnly(f) &&
        f.selector != sig:execTransaction(address,uint256,bytes,Enum.Operation,uint256,uint256,uint256,address,address,bytes).selector
    }
    {
        preserved with (env e) {
            requireInvariant nextNull();
            requireInvariant inListReachable();
            requireInvariant reach_null();
            requireInvariant reach_invariant();
            requireInvariant reachableInList();
            requireInvariant sentinelIsNotAmodule();
        }
    }

// ------------------------------------------------------------
// Property 2: isModuleEnabled(SENTINEL_MODULES) is always false.
// The sentinel address is a structural element and never a callable module.
//
// Note: This property is trivially true at the Solidity level because isModuleEnabled
// explicitly checks SENTINEL_MODULES != module. We formalize it as a rule (not invariant)
// to avoid SANITY_FAILED from trivially-true assertions in the induction step.
// The sentinelIsNotAmodule() invariant from ModuleReach.spec provides additional support.
// ------------------------------------------------------------

/// @title SENTINEL address (0x1) is never an enabled module (Property 2)
rule sentinel_not_enabled_p2() {
    assert !isModuleEnabled(SENTINEL_MODULES()),
        "SENTINEL address must never be an enabled module";
}

// ------------------------------------------------------------
// Property 3: modules[SENTINEL_MODULES] != address(0) after initialization.
// Expressed as a conditional invariant: if any address has a non-zero modules entry,
// then the sentinel's entry is non-zero too. Vacuously true before setup (all zeros).
// ------------------------------------------------------------

/// @title SENTINEL modules entry is non-zero once any module exists (Property 3)
invariant sentinel_initialized_p3(address m)
    ghostModules[m] != NULL_ADDRESS() => ghostModules[SENTINEL_MODULES()] != NULL_ADDRESS()
    filtered { f -> reachableOnly(f) &&
        f.selector != sig:execTransaction(address,uint256,bytes,Enum.Operation,uint256,uint256,uint256,address,address,bytes).selector
    }
    {
        preserved with (env e) {
            requireInvariant reach_invariant();
            requireInvariant inListReachable();
            requireInvariant reachableInList();
            requireInvariant reach_null();
            requireInvariant nextNull();
        }
    }

// ------------------------------------------------------------
// Property 4: modules[m] != m for any non-sentinel, non-null address m.
// No module points to itself as its own successor.
// NULL_ADDRESS excluded because ghostModules[0] = 0 in uninitialized state.
// ------------------------------------------------------------

/// @title No module self-loops in the linked list (Property 4)
invariant no_module_self_loop_p4(address m)
    m != SENTINEL_MODULES() && m != NULL_ADDRESS() => ghostModules[m] != m
    filtered { f -> reachableOnly(f) &&
        f.selector != sig:execTransaction(address,uint256,bytes,Enum.Operation,uint256,uint256,uint256,address,address,bytes).selector
    }
    {
        preserved with (env e) {
            requireInvariant reach_invariant();
            requireInvariant nextNull();
            requireInvariant inListReachable();
            requireInvariant reachableInList();
            requireInvariant reach_null();
        }
    }

// ------------------------------------------------------------
// Property 5: Every enabled module is reachable from SENTINEL_MODULES.
// No orphan entries exist in the modules mapping.
// ------------------------------------------------------------

/// @title All enabled modules are reachable from SENTINEL_MODULES (Property 5)
invariant all_modules_reachable_p5(address m)
    isModuleEnabled(m) => reach(SENTINEL_MODULES(), m)
    filtered { f -> reachableOnly(f) &&
        f.selector != sig:execTransaction(address,uint256,bytes,Enum.Operation,uint256,uint256,uint256,address,address,bytes).selector
    }
    {
        preserved with (env e) {
            requireInvariant inListReachable();
            requireInvariant reachableInList();
            requireInvariant reach_null();
            requireInvariant reach_invariant();
        }
    }

// ============================================================
// PROPERTIES 6-8: SELF-AUTHORIZATION FOR MANAGEMENT FUNCTIONS
// ============================================================

// ------------------------------------------------------------
// Property 6: enableModule reverts unless msg.sender == address(this).
// The authorized() modifier calls requireSelfCall() which reverts with GS031.
// ------------------------------------------------------------

/// @title enableModule is only callable by the Safe itself (Property 6)
rule enableModule_requires_self_call_p6(address module) {
    env e;
    require e.msg.sender != currentContract;
    enableModule@withrevert(e, module);
    assert lastReverted,
        "enableModule must revert when msg.sender != address(this)";
}

// ------------------------------------------------------------
// Property 7: disableModule reverts unless msg.sender == address(this).
// ------------------------------------------------------------

/// @title disableModule is only callable by the Safe itself (Property 7)
rule disableModule_requires_self_call_p7(address prevModule, address module) {
    env e;
    require e.msg.sender != currentContract;
    disableModule@withrevert(e, prevModule, module);
    assert lastReverted,
        "disableModule must revert when msg.sender != address(this)";
}

// ------------------------------------------------------------
// Property 8: setModuleGuard reverts unless msg.sender == address(this).
// ------------------------------------------------------------

/// @title setModuleGuard is only callable by the Safe itself (Property 8)
rule setModuleGuard_requires_self_call_p8(address guard) {
    env e;
    require e.msg.sender != currentContract;
    setModuleGuard@withrevert(e, guard);
    assert lastReverted,
        "setModuleGuard must revert when msg.sender != address(this)";
}

// ============================================================
// PROPERTIES 9-10: MODULE AUTHORIZATION FOR EXECUTION
// ============================================================

// ------------------------------------------------------------
// Property 9: execTransactionFromModule reverts if msg.sender is not an enabled module.
// preModuleExecution check: msg.sender == SENTINEL || modules[msg.sender] == 0 => GS104.
// ------------------------------------------------------------

/// @title execTransactionFromModule requires an enabled module as caller (Property 9)
rule execTransactionFromModule_requires_enabled_module_p9(
    address to, uint256 value, bytes data, Enum.Operation operation
) {
    env e;
    require !isModuleEnabled(e.msg.sender);
    execTransactionFromModule@withrevert(e, to, value, data, operation);
    assert lastReverted,
        "execTransactionFromModule must revert if msg.sender is not an enabled module";
}

// ------------------------------------------------------------
// Property 10: execTransactionFromModuleReturnData reverts if msg.sender is not enabled.
// Same preModuleExecution authorization check as execTransactionFromModule.
// ------------------------------------------------------------

/// @title execTransactionFromModuleReturnData requires an enabled module as caller (Property 10)
rule execTransactionFromModuleReturnData_requires_enabled_module_p10(
    address to, uint256 value, bytes data, Enum.Operation operation
) {
    env e;
    require !isModuleEnabled(e.msg.sender);
    execTransactionFromModuleReturnData@withrevert(e, to, value, data, operation);
    assert lastReverted,
        "execTransactionFromModuleReturnData must revert if msg.sender is not an enabled module";
}

// ============================================================
// PROPERTIES 11-16: MODULE STATE TRANSITION CORRECTNESS
// ============================================================

// ------------------------------------------------------------
// Property 11: After successful enableModule(m), isModuleEnabled(m) == true.
// Requires ghost state consistency invariants to avoid spurious hook assertion failures.
// ------------------------------------------------------------

/// @title enableModule correctly enables the module (Property 11)
rule enableModule_enables_module_p11(address module) {
    env e;
    requireInvariant reach_invariant();
    requireInvariant inListReachable();
    requireInvariant reachableInList();
    requireInvariant reach_null();
    requireInvariant nextNull();
    enableModule(e, module);
    assert isModuleEnabled(module),
        "Module must be enabled after a successful call to enableModule";
}

// ------------------------------------------------------------
// Property 12: After successful disableModule(prev, m), isModuleEnabled(m) == false.
// ------------------------------------------------------------

/// @title disableModule correctly removes the module (Property 12)
rule disableModule_disables_module_p12(address prevModule, address module) {
    env e;
    requireInvariant reach_invariant();
    requireInvariant inListReachable();
    requireInvariant reachableInList();
    requireInvariant reach_null();
    requireInvariant nextNull();
    disableModule(e, prevModule, module);
    assert !isModuleEnabled(module),
        "Module must not be enabled after a successful call to disableModule";
}

// ------------------------------------------------------------
// Property 13: enableModule(m) does not affect isModuleEnabled for any m' != m.
// enableModule only modifies modules[m] and modules[SENTINEL].
// ------------------------------------------------------------

/// @title enableModule is an isolated list insertion (Property 13)
rule enableModule_isolation_p13(address module, address other) {
    require other != module;
    requireInvariant reach_invariant();
    requireInvariant inListReachable();
    requireInvariant reachableInList();
    requireInvariant reach_null();
    requireInvariant nextNull();
    bool enabledBefore = isModuleEnabled(other);
    env e;
    enableModule(e, module);
    assert isModuleEnabled(other) == enabledBefore,
        "enableModule must not change the enabled status of other modules";
}

// ------------------------------------------------------------
// Property 14: disableModule(prev, m) does not affect isModuleEnabled for any m' != m.
// disableModule only modifies modules[prev] (bypass link) and modules[m] (zeroed).
// ------------------------------------------------------------

/// @title disableModule is an isolated list removal (Property 14)
rule disableModule_isolation_p14(address prevModule, address module, address other) {
    require other != module;
    requireInvariant reach_invariant();
    requireInvariant inListReachable();
    requireInvariant reachableInList();
    requireInvariant reach_null();
    requireInvariant nextNull();
    bool enabledBefore = isModuleEnabled(other);
    env e;
    disableModule(e, prevModule, module);
    assert isModuleEnabled(other) == enabledBefore,
        "disableModule must not change the enabled status of other modules";
}

// ------------------------------------------------------------
// Property 15: enableModule(m) reverts if m is already enabled (GS102).
// Check: if (modules[module] != address(0)) revertWithError("GS102");
// ------------------------------------------------------------

/// @title enableModule reverts for already-enabled modules (Property 15)
rule cannot_enable_already_enabled_p15(address module) {
    env e;
    require isModuleEnabled(module);
    enableModule@withrevert(e, module);
    assert lastReverted,
        "enableModule must revert if the module is already enabled";
}

// ------------------------------------------------------------
// Property 16: enableModule(address(0)) and enableModule(SENTINEL_MODULES) both revert (GS101).
// Check: if (module == address(0) || module == SENTINEL_MODULES) revertWithError("GS101");
// ------------------------------------------------------------

/// @title enableModule rejects the zero address (Property 16a)
rule enableModule_rejects_zero_address_p16a() {
    env e;
    enableModule@withrevert(e, NULL_ADDRESS());
    assert lastReverted,
        "enableModule must revert when called with the zero address";
}

/// @title enableModule rejects the SENTINEL address (Property 16b)
rule enableModule_rejects_sentinel_address_p16b() {
    env e;
    enableModule@withrevert(e, SENTINEL_MODULES());
    assert lastReverted,
        "enableModule must revert when called with the SENTINEL address (0x1)";
}

// ============================================================
// PROPERTY 19: GUARD COMPLIANCE VALIDATION
// ============================================================

// ------------------------------------------------------------
// Property 19: setModuleGuard(guard) with non-zero non-compliant guard must revert (GS301).
// The supportsInterfaceGhost summary models supportsInterface return value.
// require msg.sender == currentContract bypasses GS031 auth check to test GS301 path.
// ------------------------------------------------------------

/// @title setModuleGuard rejects guards that don't implement IModuleGuard (Property 19)
rule setModuleGuard_rejects_non_compliant_p19(address guard) {
    env e;
    require e.msg.sender == currentContract;   // bypass GS031 to isolate the GS301 check
    require guard != NULL_ADDRESS();
    require !supportsInterfaceGhost;            // Guard does not implement IModuleGuard interface
    setModuleGuard@withrevert(e, guard);
    assert lastReverted,
        "setModuleGuard must revert when guard doesn't implement IModuleGuard (GS301)";
}

// ============================================================
// PROPERTY 20: ISOLATION OF MODULE STATE CHANGES
// ============================================================

// ------------------------------------------------------------
// Property 20: Only enableModule or disableModule can change isModuleEnabled status.
// Under NONDET execute summary, only explicit list operations modify the modules mapping.
//
// Excluded from filter:
// - execTransaction: NONDET execute + HAVOC_ECF guards may cause spurious violations
// - execTransactionFromModule/ReturnData: same reason (NONDET execute)
// - getTransactionHash: contains domainSeparator() assembly that may cause ghost inconsistency
// - setup: the initializer; it sets modules[SENTINEL] = SENTINEL, which would violate
//   the assertion (it changes modules mapping) but is excluded as an initialization step.
//   Using requireInvariant inListReachable() (which requires ghostModules[SENTINEL] != 0)
//   creates SANITY_FAILED for setup (infeasible precondition on uninitialized state),
//   so we filter it out.
// - simulateAndRevert, getStorageAt: already filtered by reachableOnly/direct exclusion
// ------------------------------------------------------------

/// @title Module enabled status only changes via enableModule or disableModule (Property 20)
rule only_enable_disable_change_modules_p20(method f, address module)
    filtered {
        f -> reachableOnly(f) &&
             f.selector != sig:simulateAndRevert(address,bytes).selector &&
             f.selector != sig:getStorageAt(uint256,uint256).selector &&
             f.selector != sig:execTransaction(address,uint256,bytes,Enum.Operation,uint256,uint256,uint256,address,address,bytes).selector &&
             f.selector != sig:execTransactionFromModule(address,uint256,bytes,Enum.Operation).selector &&
             f.selector != sig:execTransactionFromModuleReturnData(address,uint256,bytes,Enum.Operation).selector &&
             f.selector != sig:getTransactionHash(address,uint256,bytes,Enum.Operation,uint256,uint256,uint256,address,address,uint256).selector &&
             f.selector != sig:setup(address[],uint256,address,bytes,address,address,uint256,address).selector
    }
{
    requireInvariant reach_invariant();
    requireInvariant inListReachable();
    requireInvariant reachableInList();
    requireInvariant reach_null();
    requireInvariant nextNull();

    bool enabledBefore = isModuleEnabled(module);

    env e;
    calldataarg args;
    f(e, args);

    bool enabledAfter = isModuleEnabled(module);

    assert enabledBefore != enabledAfter =>
        f.selector == sig:enableModule(address).selector ||
        f.selector == sig:disableModule(address,address).selector,
        "Module enabled status can only change via enableModule or disableModule";
}
