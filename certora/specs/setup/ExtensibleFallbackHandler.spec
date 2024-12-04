import "../problems.spec";
import "../unresolved.spec";
import "../optimizations.spec";
import "../generic.spec";

methods {
    function _.signedMessages(bytes32) external => DISPATCHER(true);
    // function _.getModulesPaginated(address,uint256) external => DISPATCHER(true);
    function _.domainSeparator() external => DISPATCHER(true);
    function _.checkSignatures(bytes32, bytes) external => DISPATCHER(true);
    function _.checkSignatures(bytes32, bytes, bytes) external => DISPATCHER(true);
    function _.isValidSafeSignature(address, address, bytes32, bytes32, bytes32, bytes, bytes) external => DISPATCHER(true);
    function _.isValidSignature(bytes32, bytes) external => DISPATCHER(true);
}

use builtin rule sanity filtered { f -> f.contract == currentContract }

// use builtin rule hasDelegateCalls filtered { f -> f.contract == currentContract }
// use builtin rule msgValueInLoopRule;
// use builtin rule viewReentrancy;
// use rule privilegedOperation filtered { f -> f.contract == currentContract }
// use rule timeoutChecker filtered { f -> f.contract == currentContract }
// use rule simpleFrontRunning filtered { f -> f.contract == currentContract }
// use rule noRevert filtered { f -> f.contract == currentContract }
// use rule alwaysRevert filtered { f -> f.contract == currentContract }
// use rule failing_CALL_leads_to_revert filtered { f -> f.contract == currentContract }