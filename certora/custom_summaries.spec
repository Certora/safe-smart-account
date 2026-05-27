// Summaries for Safe external interface interactions.
// These wildcard summaries abstract away the behavior of external actors
// that Safe interacts with, to simplify verification while remaining sound.

methods {
    // -------------------------------------------------------------------------
    // ITransactionGuard (contracts/base/GuardManager.sol)
    // Called before and after execTransaction dispatch. May revert to abort.
    // Safe reads no return values from either hook.
    // -------------------------------------------------------------------------

    /// @dev checkTransaction: policy enforcement hook called before user tx dispatch.
    ///      May have side effects on external contracts and may revert.
    function _.checkTransaction(
        address, uint256, bytes, Enum.Operation,
        uint256, uint256, uint256,
        address, address, bytes, address
    ) external => HAVOC_ECF;

    /// @dev checkAfterExecution: called after execution regardless of sub-call success.
    ///      May have side effects on external contracts and may revert.
    function _.checkAfterExecution(bytes32, bool) external => HAVOC_ECF;

    // -------------------------------------------------------------------------
    // IModuleGuard (contracts/base/ModuleManager.sol)
    // Called before and after module-initiated transactions.
    // checkModuleTransaction returns a bytes32 guard hash used to correlate pre/post.
    // -------------------------------------------------------------------------

    /// @dev checkModuleTransaction: returns a bytes32 moduleTxHash (treated as nondet).
    ///      May have side effects on external contracts and may revert.
    function _.checkModuleTransaction(
        address, uint256, bytes, Enum.Operation, address
    ) external => HAVOC_ECF;

    /// @dev checkAfterModuleExecution: called after module execution.
    ///      May have side effects on external contracts and may revert.
    function _.checkAfterModuleExecution(bytes32, bool) external => HAVOC_ECF;

    // -------------------------------------------------------------------------
    // ISignatureValidator (contracts/interfaces/ISignatureValidator.sol)
    // Called via staticcall during signature verification (v=0 in packed signatures).
    // Returns EIP-1271 magic value 0x1626ba7e for valid signatures.
    // -------------------------------------------------------------------------

    /// @dev isValidSignature: EIP-1271 contract owner validation via staticcall.
    ///      No state changes; return value (bytes4) is unconstrained.
    function _.isValidSignature(bytes32, bytes) external => NONDET;

    // -------------------------------------------------------------------------
    // ISafeSignatureVerifier (contracts/handler/extensible/SignatureVerifierMuxer.sol)
    // Domain-specific EIP-712 signature verifier called via staticcall from
    // ExtensibleFallbackHandler when a domain verifier is registered.
    // Returns EIP-1271 magic value 0x1626ba7e for valid signatures.
    // -------------------------------------------------------------------------

    /// @dev isValidSafeSignature: domain-aware EIP-712 verification via staticcall.
    ///      No state changes; return value (bytes4) is unconstrained.
    function _.isValidSafeSignature(
        address, address, bytes32, bytes32, bytes32, bytes, bytes
    ) external => NONDET;

    // -------------------------------------------------------------------------
    // IFallbackMethod / IStaticFallbackMethod (contracts/handler/extensible/ExtensibleBase.sol)
    // Both interfaces share the same function signature handle(ISafe,address,uint256,bytes).
    // IFallbackMethod: state-mutating call forwarded by ExtensibleFallbackHandler.
    // IStaticFallbackMethod: view call (staticcall) forwarded by ExtensibleFallbackHandler.
    // Using HAVOC_ECF is a sound over-approximation covering both cases.
    // -------------------------------------------------------------------------

    /// @dev handle: selector-dispatched external handler call from ExtensibleFallbackHandler.
    ///      May have side effects on external contracts; return value (bytes) is unconstrained.
    function _.handle(address, address, uint256, bytes) external => HAVOC_ECF;
}
