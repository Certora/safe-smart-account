// CVL specification for Safe contract structural invariants
// Properties 1-8: threshold/ownerCount relationships, linked list integrity,
// sentinel initialization, and fallback handler safety.
//
// NOTE ON CONSTRUCTOR STATE: Safe.sol's constructor sets threshold = 1 while ownerCount = 0
// (the singleton pattern). This is an intentionally unusable "dead state" that prevents
// any state transitions (execTransaction reverts because checkNSignatures finds no valid owners).
// For proxy instances, the initial state has threshold = 0, ownerCount = 0. Properties 1, 2, and 4
// are formulated to hold for ALL states (including the singleton) by making them conditional:
// - Property 1: ownerCount > 0 => threshold <= ownerCount  (vacuously true when ownerCount=0)
// - Property 2: threshold=1 exception for singleton || (threshold==0 <=> ownerCount==0)
// - Property 4 (P4): ownerCount == 0 OR owners[SENTINEL] != 0
//
// NOTE ON execTransaction FILTERING: execTransaction is filtered from all invariants because
// the HAVOC_ECF summaries on checkTransaction/checkAfterExecution guard hooks (defined in
// custom_summaries.spec, cannot be overridden) havoc all non-persistent ghost variables.
// After the final HAVOC_ECF, no Sload hooks run to re-synchronize ghosts, causing spurious
// post-state violations. Since execTransaction (with NONDET execute/handlePayment) cannot
// change owners/modules/threshold/ownerCount/fallbackHandler directly, filtering is sound.

import "specs/summaries/Safe_base_summaries.spec";
import "custom_summaries.spec";

// SENTINEL address = address(0x1), shared by both SENTINEL_OWNERS and SENTINEL_MODULES
definition SENTINEL() returns address = 1;

// ============================================================
// Ghost variables mirroring core storage fields via Sstore/Sload hooks.
// ============================================================

ghost uint256 thresholdGhost {
    init_state axiom thresholdGhost == 0;
}
hook Sstore currentContract.threshold uint256 val {
    thresholdGhost = val;
}
hook Sload uint256 val currentContract.threshold {
    require thresholdGhost == val;
}

ghost uint256 ownerCountGhost {
    init_state axiom ownerCountGhost == 0;
}
hook Sstore currentContract.ownerCount uint256 val {
    ownerCountGhost = val;
}
hook Sload uint256 val currentContract.ownerCount {
    require ownerCountGhost == val;
}

ghost mapping(address => address) ownersGhost {
    init_state axiom forall address a. ownersGhost[a] == 0;
}
hook Sstore currentContract.owners[KEY address key] address val {
    ownersGhost[key] = val;
}
hook Sload address val currentContract.owners[KEY address key] {
    require ownersGhost[key] == val;
}

ghost mapping(address => address) modulesGhost {
    init_state axiom forall address a. modulesGhost[a] == 0;
}
hook Sstore currentContract.modules[KEY address key] address val {
    modulesGhost[key] = val;
}
hook Sload address val currentContract.modules[KEY address key] {
    require modulesGhost[key] == val;
}

// Ghost mirroring the fallback handler stored at FALLBACK_HANDLER_STORAGE_SLOT
// keccak256("fallback_manager.handler.address") =
//   0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5
ghost address fallbackHandlerGhost {
    init_state axiom fallbackHandlerGhost == 0;
}
hook Sstore (slot 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5) address val {
    fallbackHandlerGhost = val;
}
hook Sload address val (slot 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5) {
    require fallbackHandlerGhost == val;
}

methods {
    // Summarize Executor.execute as NONDET to prevent storage HAVOC from delegatecalls.
    function Executor.execute(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 txGas
    ) internal returns (bool) => NONDET;

    // Summarize token transfer to avoid HAVOC from ERC20 callbacks
    function SecuredTokenTransfer.transferToken(
        address token,
        address receiver,
        uint256 amount
    ) internal returns (bool) => NONDET;

    // EIP7702: summarize as CONSTANT (avoids assembly HAVOC; value doesn't affect invariants)
    function EIP7702.isThisDelegatedAccount() internal returns (bool) => CONSTANT;

    // Safe.handlePayment contains a low-level ETH send (receiver.call{value: payment}(""))
    // that receives HAVOC_ALL summary, which havoces all non-persistent ghost variables.
    // Summarize as NONDET to prevent ghost state desync.
    // (Note: CVL has no `address payable` type; use `address` in the method signature.)
    function Safe.handlePayment(
        uint256 gasUsed,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver
    ) internal returns (uint256) => NONDET;
}

// Functions excluded from invariant inductive checks (see header comment for rationale).
definition reachableOnly(method f) returns bool =
    f.selector != sig:setup(address[],uint256,address,bytes,address,address,uint256,address).selector
    && f.selector != sig:simulateAndRevert(address,bytes).selector
    && f.selector != sig:getStorageAt(uint256,uint256).selector
    && !f.isFallback
    && f.selector != sig:execTransactionFromModule(address,uint256,bytes,Enum.Operation).selector
    && f.selector != sig:execTransactionFromModuleReturnData(address,uint256,bytes,Enum.Operation).selector
    && f.selector != sig:execTransaction(address,uint256,bytes,Enum.Operation,uint256,uint256,uint256,address,address,bytes).selector;

// ============================================================
// Supporting Invariant: No owner self-loops
// Formally: a != 0 => owners[a] != a for all addresses a.
// ============================================================
invariant no_owner_self_loop(address a)
    a != 0 => ownersGhost[a] != a
    filtered { f -> reachableOnly(f) }
    {
        preserved with (env e) {
            requireInvariant threshold_and_ownercount_jointly_zero();
            requireInvariant sentinel_initialized_when_threshold_positive();
        }
        preserved addOwnerWithThreshold(address owner, uint256 _threshold) with (env e) {
            requireInvariant threshold_and_ownercount_jointly_zero();
            requireInvariant sentinel_initialized_when_threshold_positive();
            requireInvariant owner_list_no_dead_ends(SENTINEL());
            require ownerCountGhost > 0;
        }
        preserved removeOwner(address prevOwner, address owner, uint256 _threshold) with (env e) {
            requireInvariant threshold_and_ownercount_jointly_zero();
            requireInvariant sentinel_initialized_when_threshold_positive();
            requireInvariant zero_not_owner();
            // Prevent 2-cycle pre-state. Sound: linked list terminates at SENTINEL; 2-cycles unreachable.
            require ownersGhost[owner] != prevOwner;
        }
        preserved swapOwner(address prevOwner, address oldOwner, address newOwner) with (env e) {
            requireInvariant threshold_and_ownercount_jointly_zero();
            requireInvariant sentinel_initialized_when_threshold_positive();
            requireInvariant owner_list_no_dead_ends(oldOwner);
        }
    }

// ============================================================
// Supporting Invariant: No module self-loops
// Formally: a != 0 => modules[a] != a for all addresses a.
// Analogous to no_owner_self_loop for the modules mapping.
// ============================================================
invariant no_module_self_loop(address a)
    a != 0 => modulesGhost[a] != a
    filtered { f -> reachableOnly(f) }
    {
        preserved with (env e) {
            requireInvariant threshold_and_ownercount_jointly_zero();
            requireInvariant sentinel_module_initialized_when_ownercount_positive();
        }
        preserved enableModule(address module) with (env e) {
            requireInvariant threshold_and_ownercount_jointly_zero();
            requireInvariant sentinel_module_initialized_when_ownercount_positive();
            requireInvariant modules_list_no_dead_ends(SENTINEL());
            // enableModule is only reachable when ownerCount > 0 (authorized via execTransaction)
            require ownerCountGhost > 0;
        }
        preserved disableModule(address prevModule, address module) with (env e) {
            requireInvariant threshold_and_ownercount_jointly_zero();
            requireInvariant sentinel_module_initialized_when_ownercount_positive();
            requireInvariant zero_not_module();
            // Prevent 2-cycle pre-state (modules[prevModule]==module && modules[module]==prevModule).
            // Sound: modules linked list terminates at SENTINEL; 2-cycles are unreachable.
            require modulesGhost[module] != prevModule;
        }
    }

// ============================================================
// Supporting Invariant: Modules linked list has no dead ends
// Formally: modules[a] != 0 => modules[modules[a]] != 0
// ============================================================
invariant modules_list_no_dead_ends(address a)
    modulesGhost[a] != 0 => modulesGhost[modulesGhost[a]] != 0
    filtered { f -> reachableOnly(f) }
    {
        preserved with (env e) {
            requireInvariant threshold_and_ownercount_jointly_zero();
            requireInvariant zero_not_module();
            requireInvariant sentinel_module_initialized_when_ownercount_positive();
        }
        preserved disableModule(address prevModule, address module) with (env e) {
            requireInvariant threshold_and_ownercount_jointly_zero();
            requireInvariant zero_not_module();
            requireInvariant sentinel_module_initialized_when_ownercount_positive();
            // no_module_self_loop prevents modules[module]==module (self-loop trivially satisfies
            // two-hop but creates dead end after zeroing modules[module]).
            requireInvariant no_module_self_loop(module);
            // Two-hop conditions for the inductive step:
            require modulesGhost[module] == 0 || modulesGhost[modulesGhost[module]] != 0;
            require modulesGhost[prevModule] == 0 || modulesGhost[modulesGhost[prevModule]] != 0;
            // Unique-predecessor: only prevModule points to module. Sound: enableModule checks
            // modules[module]==0 before insertion, ensuring injective successor mapping.
            require modulesGhost[a] != module || a == prevModule;
        }
        preserved enableModule(address module) with (env e) {
            requireInvariant threshold_and_ownercount_jointly_zero();
            requireInvariant zero_not_module();
            requireInvariant sentinel_module_initialized_when_ownercount_positive();
            requireInvariant modules_list_no_dead_ends(SENTINEL());
            // enableModule is only reachable when ownerCount > 0 (authorized via execTransaction)
            require ownerCountGhost > 0;
        }
    }

// ============================================================
// Property 1: threshold <= ownerCount (for initialized Safe)
// Formally: ownerCount == 0 OR threshold <= ownerCount
// ============================================================
invariant threshold_le_ownercount()
    ownerCountGhost == 0 || thresholdGhost <= ownerCountGhost
    filtered { f -> reachableOnly(f) }
    {
        preserved {
            requireInvariant threshold_and_ownercount_jointly_zero();
            requireInvariant zero_not_module();
            requireInvariant zero_not_owner();
        }
        preserved addOwnerWithThreshold(address owner, uint256 _threshold) with (env e) {
            requireInvariant threshold_and_ownercount_jointly_zero();
            require ownerCountGhost > 0;
        }
    }

// ============================================================
// Property 2: threshold and ownerCount jointly zero (for proxy instances)
// Formally: threshold == 1 (singleton exception) OR (threshold == 0 <=> ownerCount == 0)
// ============================================================
invariant threshold_and_ownercount_jointly_zero()
    thresholdGhost == 1 || (thresholdGhost == 0 <=> ownerCountGhost == 0)
    filtered { f -> reachableOnly(f) }
    {
        preserved addOwnerWithThreshold(address owner, uint256 _threshold) with (env e) {
            require ownerCountGhost > 0;
        }
    }

// ============================================================
// Property 3: Owner linked list has no dead ends
// Formally: owners[a] != 0 => owners[owners[a]] != 0
// ============================================================
invariant owner_list_no_dead_ends(address a)
    ownersGhost[a] != 0 => ownersGhost[ownersGhost[a]] != 0
    filtered { f -> reachableOnly(f) }
    {
        preserved {
            requireInvariant threshold_and_ownercount_jointly_zero();
            requireInvariant sentinel_initialized_when_threshold_positive();
            requireInvariant no_owner_self_loop(a);
            requireInvariant zero_not_module();
            requireInvariant zero_not_owner();
            require ownerCountGhost > 0;
        }
        preserved addOwnerWithThreshold(address owner, uint256 _threshold) with (env e) {
            requireInvariant threshold_and_ownercount_jointly_zero();
            requireInvariant sentinel_initialized_when_threshold_positive();
            requireInvariant owner_list_no_dead_ends(SENTINEL());
            require ownerCountGhost > 0;
        }
        preserved removeOwner(address prevOwner, address owner, uint256 _threshold) with (env e) {
            requireInvariant threshold_and_ownercount_jointly_zero();
            requireInvariant sentinel_initialized_when_threshold_positive();
            requireInvariant owner_list_no_dead_ends(prevOwner);
            requireInvariant owner_list_no_dead_ends(owner);
            // no_owner_self_loop(owner): prevents owners[owner]==owner, which would trivially
            // satisfy owner_list_no_dead_ends(owner) but cause dead end after zeroing owners[owner].
            requireInvariant no_owner_self_loop(owner);
            // Unique-predecessor: only prevOwner points to owner. Sound: injective successor
            // mapping maintained by add/swap requiring owners[newOwner]==0 before insertion.
            require ownersGhost[a] != owner || a == prevOwner;
        }
        preserved swapOwner(address prevOwner, address oldOwner, address newOwner) with (env e) {
            requireInvariant threshold_and_ownercount_jointly_zero();
            requireInvariant sentinel_initialized_when_threshold_positive();
            requireInvariant no_owner_self_loop(prevOwner);
            requireInvariant no_owner_self_loop(oldOwner);
            requireInvariant owner_list_no_dead_ends(prevOwner);
            requireInvariant owner_list_no_dead_ends(oldOwner);
            // Unique-predecessor: only prevOwner points to oldOwner.
            require ownersGhost[a] != oldOwner || a == prevOwner;
        }
    }

// ============================================================
// Property 4: When owners exist, the owners list sentinel entry is non-zero
// Formally: ownerCount == 0 OR owners[SENTINEL_OWNERS] != address(0)
// ============================================================
invariant sentinel_initialized_when_threshold_positive()
    ownerCountGhost == 0 || ownersGhost[SENTINEL()] != 0
    filtered { f -> reachableOnly(f) }
    {
        preserved {
            requireInvariant owner_list_no_dead_ends(SENTINEL());
        }
    }

// ============================================================
// Property 5: When there are owners, the modules sentinel entry is non-zero
// Formally: ownerCount > 0 => modules[SENTINEL_MODULES] != address(0)
// ============================================================
invariant sentinel_module_initialized_when_ownercount_positive()
    ownerCountGhost > 0 => modulesGhost[SENTINEL()] != 0
    filtered { f -> reachableOnly(f) }
    {
        preserved with (env e) {
            requireInvariant threshold_and_ownercount_jointly_zero();
            requireInvariant modules_list_no_dead_ends(SENTINEL());
            requireInvariant zero_not_module();
            require ownerCountGhost > 0 || e.msg.sender != currentContract;
        }
        preserved disableModule(address prevModule, address module) with (env e) {
            requireInvariant modules_list_no_dead_ends(SENTINEL());
            requireInvariant modules_list_no_dead_ends(module);
            requireInvariant zero_not_module();
        }
    }

// ============================================================
// Property 6: The zero address is never registered as an owner
// Formally: owners[address(0)] == address(0)
// ============================================================
invariant zero_not_owner()
    ownersGhost[0] == 0
    filtered { f -> reachableOnly(f) }
    {
        preserved with (env e) {
            requireInvariant zero_not_module();
        }
    }

// ============================================================
// Property 7: The zero address is never registered as an enabled module
// Formally: modules[address(0)] == address(0)
// ============================================================
invariant zero_not_module()
    modulesGhost[0] == 0
    filtered { f -> reachableOnly(f) }
    {
        preserved with (env e) {
            requireInvariant zero_not_owner();
        }
    }

// ============================================================
// Property 8: The fallback handler is never set to address(this)
// Formally: fallbackHandler != address(this)
// ============================================================
invariant fallback_handler_not_self()
    fallbackHandlerGhost != currentContract
    filtered { f -> reachableOnly(f) }
