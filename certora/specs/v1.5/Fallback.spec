/* A specification for the exstensible fallback handler */

using ExtensibleFallbackHandlerHarness as fallbackHandler;
using DummyHandler as dummyHandler;
using DummyStaticHandler as dummyStaticHandler;
using SafeHarness as safe;

// ---- Methods block ----------------------------------------------------------
methods {

    function getFallbackHandler() external returns (address) envfree;
    
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
/// @status Done: https://prover.certora.com/output/39601/edb75f86f23445cdbc7cd7b5c4c420b6?anonymousKey=62191f4f70404bcbce784f5172e3ed7ab323d416
invariant fallbackHanlderNeverSelf() 
    getFallbackHandler() != safe
    filtered { 
        f -> f.selector != sig:simulateAndRevert(address,bytes).selector 
    }

// for soundness of fallbackHanlderNeverSelf, we prove a rule that simulateAndRevert always reverts
rule simulateAndRevertReverts(address caddr, bytes b) {
    env e;
    simulateAndRevert@withrevert(e,caddr,b);
    assert lastReverted;
}

/// @dev 3 rules for set safe method integrity: sets/modifies/removes handler
/// @status Done: https://prover.certora.com/output/39601/bab9860cdfc44a83bed82e79d8c06218?anonymousKey=b4c5dbef050bb201ad78b3dd5af5cdca8ffa9f92
rule setSafeMethodSets(bytes4 selector, address newMethodCaddr) {
    env e; 

    bytes32 newMethod = to_bytes32(assert_uint256(newMethodCaddr));

    fallbackHandler.setSafeMethod(e,selector,newMethod);
    bytes32 thisMethod = fallbackHandler.getSafeMethod(e,e.msg.sender,selector);

    assert (thisMethod == thisMethod);
}

/// @status Done: https://prover.certora.com/output/39601/8591535c4a434f3e826af00b95ea1ca8?anonymousKey=a7b6743a3161a3289883f99014619a9d6e7196e1
/// note this is a special case of the rule above, but we still include it here for illustration
rule setSafeMethodRemoves(bytes4 selector) {
    env e; 

    bytes32 newMethod = to_bytes32(0); // call setSafeMethod with the zero address

    fallbackHandler.setSafeMethod(e,selector,newMethod);
    bytes32 thisMethod = fallbackHandler.getSafeMethod(e,e.msg.sender,selector);

    assert (thisMethod == to_bytes32(0)); // there is nothing stored
}

/// @status Done: https://prover.certora.com/output/39601/b44efe9ef3bd4ff5a1af710a7d3d7ee4?anonymousKey=7fd15cc355164c803123c27b41660fed34548647 
rule setSafeMethodChanges(bytes4 selector, address newMethodCaddr) {
    env e; 

    bytes32 newMethod = to_bytes32(assert_uint256(newMethodCaddr));
    bytes32 oldMethod = fallbackHandler.getSafeMethod(e,e.msg.sender,selector);
    require (newMethod != oldMethod); // we are changing the method address

    fallbackHandler.setSafeMethod(e,selector,newMethod);

    bytes32 thisMethod = fallbackHandler.getSafeMethod(e,e.msg.sender,selector);

    assert (thisMethod == newMethod);
}


/// @dev a handler, once set via setSafeMethod, is possible to call
/// @status Done: https://prover.certora.com/output/39601/9fcde04ecd434963b9ce788f7ddea8c1?anonymousKey=a7efde58b28ef7c99264424b66984a8d39b78518
rule hanlderCallableIfSet(method f) filtered { f -> f.isFallback } {
    env e;

    // the fallback handler is in the scene
    require (getFallbackHandler() == fallbackHandler);

    // the dummy (sub) handler is a valid handler for this safe
    bytes32 dummy_bytes = to_bytes32(assert_uint256(dummyHandler));
    bytes4 selector = to_bytes4(00); // 0x00 indicates this is a non-static call
    fallbackHandler.setSafeMethod(e,selector,dummy_bytes); // we've set the dummy as a handler

    // reset the check to see if dummy handler has been called
    dummyHandler.resetMethodCalled(e);

    // call the fallback method of the Safe contract
    calldataarg args ;
    f(e,args);

    // there is an execution path that calls the connected dummy handler
    satisfy (dummyHandler.methodCalled(e));
}