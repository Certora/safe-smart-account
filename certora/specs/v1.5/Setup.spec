/* A specification for the Safe setup function */


// ---- Methods block ----------------------------------------------------------
methods {
    function getThreshold() external returns (uint256) envfree;

    function SecuredTokenTransfer.transferToken(address token, address receiver, uint256 amount) internal returns (bool) => NONDET ;
}

// ---- Functions and ghosts ---------------------------------------------------


// ---- Invariants -------------------------------------------------------------


// ---- Rules ------------------------------------------------------------------

/// @dev setup can only be called if threshold = 0
/// @status Done: https://prover.certora.com/output/39601/202435585f914643abd02fe37b8d1fc5?anonymousKey=e74abb4876b18456b372d84e44ad78e3a22a0566

rule setupThresholdZero(
        address[] _owners,
        uint256 _threshold,
        address to,
        bytes data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address paymentReceiver) {
    env e;

    uint256 old_threshold = getThreshold();

    // a successful call to setup
    setup(e,_owners,_threshold,to,data,fallbackHandler,
        paymentToken,payment,paymentReceiver);

    assert (old_threshold == 0);
}

/// @dev setup sets threshold > 0 
/// @status Done: https://prover.certora.com/output/39601/202435585f914643abd02fe37b8d1fc5?anonymousKey=e74abb4876b18456b372d84e44ad78e3a22a0566 

rule setupSetsPositiveThreshold(
        address[] _owners,
        uint256 _threshold,
        address to,
        bytes data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address paymentReceiver) {
    env e;

    // a successful call to setup
    setup(e,_owners,_threshold,to,data,fallbackHandler,
        paymentToken,payment,paymentReceiver);
    
    uint256 new_threshold = getThreshold();

    assert (new_threshold > 0);
}