
methods {
    // WETH
    // function _.deposit() external => DISPATCHER(true);
    // function _.withdraw(uint256) external => DISPATCHER(true);
}

use builtin rule sanity;


// all Exchange functions are not envfree and require this on their env.
function callExchangeNotFromWeth(env e) {
    require e.msg.sender != WETH;
}

// force going through CALLs and STATICCALLs
ghost bool madeACall;
ghost uint32 selectorUsed;

hook CALL(uint g, address addr, uint value, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc {
    madeACall = true;
    selectorUsed = selector;
}

hook STATICCALL(uint g, address addr, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc {
    madeACall = true;
    selectorUsed = selector;
}

function makeACall(method f) {
    madeACall = false;
    env e;
    if (f.contract == currentContract) {
        callExchangeNotFromWeth(e);
    }
    calldataarg arg;
    f(e, arg);
    require madeACall;
}

rule hadACall {
    method f;
    makeACall(f);
    satisfy true;
}

rule hadACallToTransfer {
    method f;
    makeACall(f);
    satisfy to_mathint(selectorUsed) == 0xa9059cbb;
}


rule hadACallToTransferFrom {
    method f;
    makeACall(f);
    satisfy to_mathint(selectorUsed) == 0x23b872dd;
}