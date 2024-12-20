/* A specification for the Safe setup function */


// ---- Methods block ----------------------------------------------------------
methods {
    function getThreshold() external returns (uint256) envfree;

    function SecuredTokenTransfer.transferToken(address token, address receiver, uint256 amount) internal returns (bool) => NONDET ;
}

// ---- Functions and ghosts ---------------------------------------------------


// ---- Invariants -------------------------------------------------------------


// ---- Rules ------------------------------------------------------------------

/// @dev approvedHashes[user][hash] can only be changed by msg.sender==user
/// @status Done: https://prover.certora.com/output/39601/bb515eafa67e4edd99bb5aa51a63877b?anonymousKey=9c42e3105c1c3a3fbc95c8a24fa43b3dd43a05d6 

rule approvedHashesUpdate(method f,bytes32 userHash,address user) filtered {
    f -> f.selector != sig:simulateAndRevert(address,bytes).selector
} {
    env e;

    uint256 hashBefore = approvedHashVal(e,user,userHash);

    calldataarg args;
    f(e,args);

    uint256 hashAfter = approvedHashVal(e,user,userHash);

    assert (hashBefore != hashAfter =>
        (e.msg.sender == user)
    );
}


/// @dev approvedHashes is set when calling approveHash
/// @status Done: https://prover.certora.com/output/39601/bb515eafa67e4edd99bb5aa51a63877b?anonymousKey=9c42e3105c1c3a3fbc95c8a24fa43b3dd43a05d6

rule approvedHashesSet(bytes32 hashToApprove) {
    env e;
    approveHash(e,hashToApprove);
    assert(approvedHashVal(e,e.msg.sender,hashToApprove) == 1);
}