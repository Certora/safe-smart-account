/* Functional Specifications (unit tests) for:
    OwnerManager, ModuleManager, GuardManager */


// ---- Methods block ----------------------------------------------------------
methods {
    function getThreshold() external returns (uint256) envfree;
    // owners
    function getOwnerCount() external returns (uint256) envfree;
    function getOwners() external returns (address[] memory) envfree;
    function isOwner(address) external returns (bool) envfree;
    // modules
    function isModuleEnabled(address) external returns (bool) envfree;
    // guard 
    function getGuardExternal() external returns (address) envfree;

}

// ---- Functions and ghosts ---------------------------------------------------



// ---- Rules and Invariants ---------------------------------------------------


// ---- owner management 

/// @dev owners are only updated by a reentrant call
/// @status TODO
rule ownerMgmtPermissions() {
    env e;

    assert true;
}

/// @dev if you remove an owner, it's no longer an owner
/// @status Done: https://prover.certora.com/output/39601/41735216344e42df917455cc66e7bae1?anonymousKey=3a718e7932db72b3e68dec9597d1f30f36c3dca8
rule ownerRemoved(address prevOwner, address owner, uint256 _threshold) {
    env e;
    removeOwner(e,prevOwner,owner,_threshold);
    assert !isOwner(owner);
}


/// @dev if you add an owner, the owner is now an owner
/// @status violated: https://prover.certora.com/output/39601/e52e905b6d7442a294807e53245833cf?anonymousKey=9a13504825edbe671643d97ee6ae6893ec23b96a
rule ownerAdded(address owner, uint256 _threshold) {
    env e;
    // requireInvariant ownerNeverZero();
    requireInvariant ownerConsistency();
    addOwnerWithThreshold(e,owner,_threshold);
    assert isOwner(owner);
}

/// @status violated: https://prover.certora.com/output/39601/0e74cc48e1334c9d88bf9004afa84f7a?anonymousKey=24490e8299b1f352cb8e188d823040803d4df038
invariant ownerNeverZero()
    isOwner(0) == false ;

/// @dev swapping an owner is equivalent to removing and then adding that owner
/// @status TODO
rule ownerSwap(address prevOwner, address oldOwner, address newOwner, uint256 _threshold) {
    env e;
    storage init = lastStorage;

    // swap an owner
    swapOwner(e,prevOwner,oldOwner,newOwner);

    // [ TODO gather some information ]

    // remove and then add
    removeOwner(e,prevOwner,oldOwner,_threshold) at init;
    addOwnerWithThreshold(e,newOwner,_threshold);

    // [ TODO gather some information ]

    // TODO some metric of equality
    assert true;
}

/// @dev the variables managing owner count are all consistent
/// @status Done: https://prover.certora.com/output/39601/7a6072930d724e808d51cd90864cd953?anonymousKey=d53e3367e249eb577a448583b9d55eef3ee9dbb0
/// (maybe not) https://prover.certora.com/output/39601/e110e62abc564628b301f1c627d82b59?anonymousKey=cbd9691b46d5438041d9cab6b2c916654f6a437e
invariant ownerConsistency()
    getOwnerCount() == getOwners().length ;


/// @dev always at least 1 owner
/// @status violated: https://prover.certora.com/output/39601/1df7b563038246fcab5cb6c2217ae35a?anonymousKey=667b1387b888fb92f15de79d4c3fc52a98e4769d
invariant ownerMin()
    getOwnerCount() >= 1;

// ---- module management 

/// @dev modules are only managed by permissioned address
/// @status TODO
rule modMgmtPermissions() {
    env e;
    

    assert true;
}

/// @dev if you disable a module, it's no longer a module
/// @status Done: https://prover.certora.com/output/39601/f79f12b11e0a41d4a088d9fdbf0dcb89?anonymousKey=daf189a947c29c51cb5cec06e75c82f23fd183a7
rule moduleDisabled(address prevModule, address module) {
    env e;
    disableModule(e,prevModule,module);
    assert !isModuleEnabled(module);
}

/// @dev if you enable a module, it's a module
/// @status violated: https://prover.certora.com/output/39601/906f7f9de4194d4da30857aaf827d65f?anonymousKey=baf8696bd23bb662aa079ff51d3853ddfb253fdb
rule moduleEnabled(address module) {
    env e;
    enableModule(e,module);
    // requireInvariant moduleNeverZero();
    assert isModuleEnabled(module);
}

/// @status working
invariant moduleNeverZero()
    isModuleEnabled(0) == false ;


// ---- guard management 

/// @dev guards are only managed by permissioned address
/// @status TODO
rule guardMgmtPermissions() {
    env e;

    assert true;
}

/// @dev set-get relationship
/// @status Done: https://prover.certora.com/output/39601/aaa215b666354c19b30123295607324c?anonymousKey=ca12f804a39677cbcebef93502fc683b6ad21dbf
rule setGetRelationship(address guard) {
    env e;
    setGuard(e,guard);
    address gotGuard = getGuardExternal();
    assert guard == gotGuard;
}

// ---- threshold 

/// @dev threshold <= # owners
/// @status Done: https://prover.certora.com/output/39601/edd587c97cf644a6b4fd314c3fda4c78?anonymousKey=7a6fff9eb78da39b89aa9358a5a1ca8eb6cc0df3
rule thresholdBoundedAbove(uint256 _threshold) {
    env e;

    changeThreshold(e,_threshold);

    uint256 this_threshold = getThreshold() ;
    uint256 this_ownerCount = getOwnerCount() ;

    assert this_threshold <= this_ownerCount;
}

/// @dev threshold <= # owners
/// @status violated: https://prover.certora.com/output/39601/3595e9aa315d4b5da6e22900129d2128?anonymousKey=8ddd4deb7a0275512e00bb50091f02d5dff89dc0
invariant thresholdBoundedByOwnerCount()
    getThreshold() <= getOwnerCount() ;

/// @dev if I change threshold, I can always change it again
/// @status TODO
rule thresholdLiveness() {
    env e;
    

    assert true;
}

