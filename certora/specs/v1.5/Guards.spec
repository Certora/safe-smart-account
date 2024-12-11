/* A specification of the safe guard and module guard */

using ModuleGuardMock as modGuardMock;
using TxnGuardMock as txnGuardMock;

// ---- Methods block ----------------------------------------------------------
methods {

    function getModuleGuardExternal() external returns (address) envfree;
    function getSafeGuard() external returns (address) envfree;

    // function _.checkModuleTransaction() external => DISPATCHER(true) ;
    // function _.checkTransaction() external => DISPATCHER(true) ;

}

// ---- Functions and ghosts ---------------------------------------------------


// ---- Invariants -------------------------------------------------------------


// ---- Rules ------------------------------------------------------------------

/// @dev the only method that can change the guard is setGuard
/// @status Done: https://prover.certora.com/output/39601/ad60a9c202954b4283d79dd289b97528?anonymousKey=9b2a693359d9ed0ca6cc8aeefacec73bfa0fc82e
rule guardAddressChange(method f) filtered {
    f -> f.selector != sig:simulateAndRevert(address,bytes).selector &&
         f.selector != sig:getStorageAt(uint256,uint256).selector
} {
    address guardBefore = getSafeGuard();

    calldataarg args; env e;
    f(e, args);

    address guardAfter = getSafeGuard();

    assert guardBefore != guardAfter =>
        f.selector == sig:setGuard(address).selector;
}

/// @dev the only method that can change the module guard is setModuleGuard
/// @status Done: https://prover.certora.com/output/39601/b23bd2ee79df48129ddf6c0b8269e1a7?anonymousKey=126c42543f362c5724d530a6dd9e8521da5b0c02

rule moduleGuardAddressChange(method f) filtered {
    f -> f.selector != sig:simulateAndRevert(address,bytes).selector &&
         f.selector != sig:getStorageAt(uint256,uint256).selector
} {
    address guardBefore = getModuleGuardExternal();
    
    calldataarg args; env e;
    f(e,args);
    
    address guardAfter = getModuleGuardExternal();

    assert guardBefore != guardAfter => 
        f.selector == sig:setModuleGuard(address).selector;
}

/// @dev set-get correspondence for (regular) guard
/// @status Done: https://prover.certora.com/output/39601/b23bd2ee79df48129ddf6c0b8269e1a7?anonymousKey=126c42543f362c5724d530a6dd9e8521da5b0c02
rule setGetCorrespondenceGuard(address guard) {
    env e;
    setGuard(e,guard);
    address gotGuard = getSafeGuard();
    assert guard == gotGuard;
}

/// @dev set-get correspodnence for module guard
/// @status Done: https://prover.certora.com/output/39601/b23bd2ee79df48129ddf6c0b8269e1a7?anonymousKey=126c42543f362c5724d530a6dd9e8521da5b0c02
rule setGetCorrespondenceModuleGuard(address guard) {
    env e;
    setModuleGuard(e,guard);
    address gotGuard = getModuleGuardExternal();
    assert guard == gotGuard;
}

/// @dev the transaction guard works: if the transaction succeeds then the transaction guard succeeds
/// @status working
rule txnGuardCalled(
    address to,
    uint256 value,
    bytes data,
    Enum.Operation operation,
    uint256 safeTxGas,
    uint256 baseGas,
    uint256 gasPrice,
    address gasToken,
    address refundReceiver,
    bytes signatures
) {
    env e;

    execTransaction(e,to,value,data,operation,safeTxGas,baseGas,
        gasPrice,gasToken,refundReceiver,signatures);

    address guard = getSafeGuard();
    require (guard != 0); // there is a transaction guard
    
    txnGuardMock.checkTransaction@withrevert(e,to,value,data,operation,safeTxGas,baseGas,
        gasPrice,gasToken,refundReceiver,signatures,e.msg.sender);
    assert !lastReverted; // the guard succeeded
}

/// @dev the module guard works: if the transaction succeeds then the module guard succeeds
/// @status working
rule moduleGuardCalled(
        address to,
        uint256 value,
        bytes data,
        Enum.Operation operation) {
    env e;
    
    execTransactionFromModule(e,to,value,data,operation);
    
    address guard = getModuleGuardExternal();
    require (guard != 0); // there is a module guard

    modGuardMock.checkModuleTransaction@withrevert(e, to, value, data, operation, e.msg.sender);
    assert !lastReverted; // the guard succeeded
}

