/* A specification for the exstensible fallback handler */

using ExtensibleFallbackHandlerHarness as fallbackHandler;
using DummyHandler as dummyHandler;
using SafeHarness as safe;

// ---- Methods block ----------------------------------------------------------
methods {

    function getFallbackHandler() external returns (address) envfree;
    function _.handle(address _safe, address sender, uint256 value, bytes data) external => DISPATCHER(true);

    unresolved external in safe._ => DISPATCH(use_fallback=true) [
        fallbackHandler._
    ] default NONDET;
    
    unresolved external in callDummyHandler(bytes4) => DISPATCH(use_fallback=true) [
        safe._
    ] default NONDET;

}

// ---- Functions and ghosts ---------------------------------------------------



// ---- Invariants -------------------------------------------------------------



// ---- Rules ------------------------------------------------------------------

/// @dev fallback handler gets set by setFallbackHandler
rule setFallbackIntegrity(address handler) {
    env e;

    setFallbackHandler(e,handler);
    address this_handler = getFallbackHandler();

    assert (this_handler == handler);
}

/// @dev invariant: the address in fallback handler slot is never self
invariant fallbackHandlerNeverSelf() 
    getFallbackHandler() != safe
    filtered { 
        f -> f.selector != sig:simulateAndRevert(address,bytes).selector 
    }

/// @dev for soundness of fallbackHandlerNeverSelf, we prove a rule that simulateAndRevert always reverts
rule simulateAndRevertReverts(address caddr, bytes b) {
    env e;
    simulateAndRevert@withrevert(e,caddr,b);
    assert lastReverted;
}

/// @dev setSafeMethod sets the handler
rule setSafeMethodSets(bytes4 selector, address newMethodCaddr) {
    env e;

    bytes32 newMethod = to_bytes32(assert_uint256(newMethodCaddr));

    fallbackHandler.setSafeMethod(e,selector,newMethod);
    // callSetSafeMethod(e,selector,newMethod);
    bytes32 thisMethod = fallbackHandler.getSafeMethod(e,e.msg.sender,selector);

    assert (thisMethod == newMethod);
}

/// @dev setSafeMethod removes the handler
rule setSafeMethodRemoves(bytes4 selector) {
    env e; 

    bytes32 newMethod = to_bytes32(0); // call setSafeMethod with the zero address

    fallbackHandler.setSafeMethod(e,selector,newMethod);
    // callSetSafeMethod(e,selector,newMethod);
    bytes32 thisMethod = fallbackHandler.getSafeMethod(e,e.msg.sender,selector);

    assert (thisMethod == to_bytes32(0)); // there is nothing stored
}

/// @dev setSafeMethod changes the handler
rule setSafeMethodChanges(bytes4 selector, address newMethodCaddr) {
    env e; 

    bytes32 newMethod = to_bytes32(assert_uint256(newMethodCaddr));
    bytes32 oldMethod = fallbackHandler.getSafeMethod(e,e.msg.sender,selector);
    require (newMethod != oldMethod); // we are changing the method address

    fallbackHandler.setSafeMethod(e,selector,newMethod);
    // callSetSafeMethod(e,selector,newMethod);
    
    bytes32 thisMethod = fallbackHandler.getSafeMethod(e,e.msg.sender,selector);

    assert (thisMethod == newMethod);
}


/// @dev a handler, once set via setSafeMethod, is possible to call
rule handlerCallableIfSet(method f, bytes4 selector) filtered { f -> f.isFallback } {
    env e;

    // the fallback handler is in the scene
    require (getFallbackHandler() == fallbackHandler);

    // the dummy (sub) handler is a valid handler for this safe
    bytes32 dummy_bytes = to_bytes32(assert_uint256(dummyHandler));
    fallbackHandler.setSafeMethod(e,selector,dummy_bytes); // we've set the dummy as a handler

    // reset the check to see if dummy handler has been called
    dummyHandler.resetMethodCalled(e);

    // call the fallback method of the Safe contract
    calldataarg args ;
    f(e,args);

    // there is an execution path that calls the connected dummy handler
    satisfy (dummyHandler.methodCalled(e));
}

/// @dev a handler is called under expected conditions
rule handlerCalledIfSet() {
    env e;

    // the fallback handler is in the scene
    require (getFallbackHandler() == fallbackHandler);

    // the dummy (sub) handler is a valid handler for this safe
    bytes32 dummy = to_bytes32(assert_uint256(dummyHandler));
    bytes4 selector = to_bytes4(sig:dummyHandler.dummyMethod().selector);
    callSetSafeMethod(e,selector,dummy); // we've set the dummy as a handler

    // reset the check to see if dummy handler has been called
    dummyHandler.resetMethodCalled(e);

    callDummyHandler(e,selector);

    // there is an execution path that calls the connected dummy handler
    assert (dummyHandler.methodCalled(e));
}