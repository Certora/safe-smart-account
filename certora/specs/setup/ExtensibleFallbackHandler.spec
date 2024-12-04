import "../problems.spec";
import "../unresolved.spec";
import "../optimizations.spec";


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

