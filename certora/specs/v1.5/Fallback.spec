/* A specification for the exstensible fallback handler */

using ExtensibleFallbackHandlerHarness as fallbackHandler;
using DummyHandler as dummyHandler;
using DummyStaticHandler as dummyStaticHandler;
using SafeHarness as safe;

// ---- Methods block ----------------------------------------------------------
methods {

    function getFallbackHandler() external returns (address) envfree;
    function addressToBytes32(address) external returns (bytes32) envfree;

    function _.handle(address _safe, address sender, uint256 value, bytes data) external => DISPATCHER(true);
}

// ---- Functions and ghosts ---------------------------------------------------



// ---- Invariants -------------------------------------------------------------



// ---- Rules ------------------------------------------------------------------

/// @dev fallback handler gets set by setFallbackHandler
/// @status Done: https://prover.certora.com/output/39601/ab995049df0b454b888f3cd6a27331d5?anonymousKey=1a710fa917c8c60a9a420e026d6570d91e1e923b
rule setFallbackIntegrity(address handler) {
    env e;

    setFallbackHandler(e,handler);
    address this_handler = getFallbackHandler();

    assert (this_handler == handler);
}

/// @dev invariant: the address in fallback handler slot is never self
/// @status Done (?)s: https://prover.certora.com/output/39601/103eb341ceef481c830e0ba04eb06766?anonymousKey=61cb4fd6726ab3d0fad887f6393865263eecf3f0
invariant fallbackHanlderNeverSelf()
    getFallbackHandler() != safe ;


/// @dev set safe method integrity: sets/modifies/removes handler  
/// @status Done: https://prover.certora.com/output/39601/09912f9691e04917b4c0277e30ad8e38?anonymousKey=61db5fd06c13a287939455e3a531ff841442ee2e
rule setSafeMethodIntegrity(bytes4 selector, address newMethod_addr) {
    env e; 

    bytes32 newMethod = addressToBytes32(newMethod_addr);

    fallbackHandler.setSafeMethod(e,selector,newMethod);
    bytes32 this_method = fallbackHandler.getSafeMethod(e,e.msg.sender,selector);

    assert (newMethod == this_method);
}


/// @dev a handler, once set via setSafeMethod, is possible to call
/// @status Done: https://prover.certora.com/output/39601/9fcde04ecd434963b9ce788f7ddea8c1?anonymousKey=a7efde58b28ef7c99264424b66984a8d39b78518
rule hanlderCallableIfSet(bytes4 selector,method f) filtered { f -> f.isFallback } {
    env e;

    // the fallback handler is in the scene
    require (getFallbackHandler() == fallbackHandler);

    // the dummy (sub) handler is a valid handler for this safe
    bytes32 dummy_bytes = addressToBytes32(dummyHandler); // TODO to_bytes32 from CVL2
    //  bytes4 selector = to_bytes4(00); // 0x00 indicates this is a non-static call
    fallbackHandler.setSafeMethod(e,selector,dummy_bytes); // we've set the dummy as a handler

    // reset the check to see if dummy handler has been called
    dummyHandler.resetMethodCalled(e);

    // call the fallback method of the Safe contract
    calldataarg args ;
    f(e,args);

    // there is an execution path that calls the connected dummy handler
    satisfy (dummyHandler.methodCalled(e));
}