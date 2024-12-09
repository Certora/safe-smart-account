import "../generic.spec";

methods {
    // BaseGuard (e.g. DebugTransactionGuard) is both IModuleGuard and ITransactionGuard
    // IModuleGuard
    function _.checkModuleTransaction(address,uint256,bytes,Enum.Operation,address) external => DISPATCHER(true);
    function _.checkAfterModuleExecution(bytes32, bool) external => DISPATCHER(true);
    // IModuleGuard is IERC165
    function _.supportsInterface(bytes4) external => DISPATCHER(true); 
    // ITransactionGuard
    function _.checkTransaction(address, uint256, bytes, Enum.Operation, uint256, uint256, uint256, address, address, bytes, address) external => DISPATCHER(true);
    function _.checkAfterExecution(bytes32, bool) external => DISPATCHER(true);

    // Safe
//    function _.checkSignatures(bytes32, bytes) external => DISPATCHER(true);
//    function _.checkSignatures(bytes32, bytes, bytes) external => DISPATCHER(true);
//    function _.signedMessages(bytes32, uint256) external => DISPATCHER(true);
//    function _.domainSeparator() external => DISPATCHER(true);
    function _.nonce() external => DISPATCHER(true);
    function _.getTransactionHash(address,uint256,bytes,Enum.Operation,uint256,uint256,uint256,address,address,uint256) external => DISPATCHER(true);

    // ISignatureValidator (e.g. CompatibilityFallbackHandler)
//    function _.isValidSignature(bytes32, bytes) external => DISPATCHER(true);

    // ISafeSignatureVerifier (e.g. TestSafeSignatureVerifier)
//    function _.isValidSafeSignature(address, address, bytes32, bytes32, bytes32, bytes, bytes) external => DISPATCHER(true);


    function Safe.checkContractSignature(address, bytes32, bytes memory, uint256) internal => NONDET;
    function SignatureDecoder.signatureSplit(bytes memory signatures, uint256 pos) internal returns (uint8,bytes32,bytes32) => signatureSplitGhost(signatures,pos);
}

persistent ghost mapping(bytes => mapping(uint256 => uint8)) mySigSplitV;
persistent ghost mapping(bytes => mapping(uint256 => bytes32)) mySigSplitR;
persistent ghost mapping(bytes => mapping(uint256 => bytes32)) mySigSplitS;

function signatureSplitGhost(bytes signatures, uint256 pos) returns (uint8,bytes32,bytes32) {
    return (mySigSplitV[signatures][pos], mySigSplitR[signatures][pos], mySigSplitS[signatures][pos]);
}

use builtin rule sanity filtered { f -> f.contract == currentContract && f.selector != sig:simulateAndRevert(address,bytes).selector }
use builtin rule hasDelegateCalls filtered { f -> f.contract == currentContract }
use builtin rule msgValueInLoopRule;
use builtin rule viewReentrancy;
use rule privilegedOperation filtered { f -> f.contract == currentContract }
use rule timeoutChecker filtered { f -> f.contract == currentContract }
use rule simpleFrontRunning filtered { f -> f.contract == currentContract }
use rule noRevert filtered { f -> f.contract == currentContract }
use rule alwaysRevert filtered { f -> f.contract == currentContract }
use rule failing_CALL_leads_to_revert filtered { f -> f.contract == currentContract }