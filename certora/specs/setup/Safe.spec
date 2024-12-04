import "../problems.spec";
import "../unresolved.spec";
import "../optimizations.spec";

methods {
    function _.supportsInterface(bytes4) external => DISPATCHER(true);
    function _.checkModuleTransaction(address,uint256,bytes,Enum.Operation,address) external => DISPATCHER(true);
    function _.checkAfterModuleExecution(bytes32, bool) external => DISPATCHER(true);
}


use builtin rule sanity filtered { f -> f.contract == currentContract }
