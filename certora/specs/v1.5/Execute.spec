/* A specification for the exstensible fallback handler */

using ModuleGuardMock as modGuardMock;
using TxnGuardMock as txnGuardMock;
using SafeHarness as safe;

// ---- Methods block ----------------------------------------------------------
methods {

    // envfree
    function numSigsSufficient(bytes signatures,uint256 requiredSignatures) external returns (bool) envfree;

    // function _.isValidSignature(bytes32 _hash, bytes _signature) external => DISPATCHER(true);

    function _.checkTransaction(
        address to,
        uint256 value,
        bytes data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        bytes signatures,
        address msgSender
    ) external => DISPATCHER(true) ;

    function _.checkAfterExecution(bytes32 hash, bool success) external 
        => DISPATCHER(true);

    function Executor.execute(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 txGas
    ) internal returns (bool) => NONDET;

    function SecuredTokenTransfer.transferToken(address token, address receiver, uint256 amount) internal returns (bool) => NONDET ;
    function Safe.handlePayment(
        uint256 gasUsed,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver
    ) internal returns (uint256) => NONDET ;

}

// ---- Functions and ghosts ---------------------------------------------------


// ---- Invariants -------------------------------------------------------------


// ---- Rules ------------------------------------------------------------------

/// @dev a successful call to execTransactionFromModule must be from enabled module
/// @status Done: https://prover.certora.com/output/39601/dcc09acbeead4df9868519a4ac0e3ee5?anonymousKey=327efa3ac9dde7907db389b3a2688ce42094ef41
rule execTxnModulePermissions(
        address to,
        uint256 value,
        bytes data,
        Enum.Operation operation) {
    env e;

    // execTxn from module passes
    execTransactionFromModule(e,to,value,data,operation);
    
    // msg sender is the module
    assert (isModuleEnabled(e,e.msg.sender));
}


/// @dev at least "threshold" signatures provided
/// @status Done: https://prover.certora.com/output/39601/9f364fac5e8c43e0acc2d93cea3f5560?anonymousKey=d37fb383bff8fa2fe0dacf60b61130e1aadf2ad4
rule executeThresholdMet(
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
    uint256 threshold = getThreshold(e);

    // a call to execTxn succeeds
    execTransaction(e,to,value,data,operation,safeTxGas,baseGas,
        gasPrice,gasToken,refundReceiver,signatures);
    
    assert (numSigsSufficient(signatures,threshold));
}