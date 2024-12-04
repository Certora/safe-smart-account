import "../problems.spec";
import "../unresolved.spec";
import "../optimizations.spec";
import "../generic.spec";

methods {
    function _.supportsInterface(bytes4) external => DISPATCHER(true);
    function _.checkModuleTransaction(address,uint256,bytes,Enum.Operation,address) external => DISPATCHER(true);
    function _.checkAfterModuleExecution(bytes32, bool) external => DISPATCHER(true);
}


use builtin rule sanity filtered { f -> f.contract == currentContract && f.selector != sig:simulateAndRevert(address,bytes).selector }
// use builtin rule hasDelegateCalls filtered { f -> f.contract == currentContract }
// use builtin rule msgValueInLoopRule;
// use builtin rule viewReentrancy;
// use rule privilegedOperation filtered { f -> f.contract == currentContract }
// use rule timeoutChecker filtered { f -> f.contract == currentContract }
// use rule simpleFrontRunning filtered { f -> f.contract == currentContract }
// use rule noRevert filtered { f -> f.contract == currentContract }
// use rule alwaysRevert filtered { f -> f.contract == currentContract }
// use rule failing_CALL_leads_to_revert filtered { f -> f.contract == currentContract }