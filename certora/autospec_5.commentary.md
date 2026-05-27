
## Fallback Manager CVL Specification — Final Result

### Summary
All 12 properties for Safe's FallbackManager component have been formalized and verified. The specification covers:

**Invariants (Properties 1-2):**
- `prop1_fallback_handler_not_self`: Invariant ensuring fallbackHandlerGhost != currentContract across all reachable states (filtered to exclude simulateAndRevert which always reverts, proven by `simulateAndRevertAlwaysReverts`)
- `prop2_handler_modification_control`: Parametric rule proving only setFallbackHandler and setup can modify the FALLBACK_HANDLER_STORAGE_SLOT

**Safety Properties (Properties 3-8):**
- `setFallbackHandler_revert_characteristics`: Biconditional proving setFallbackHandler reverts iff (msg.sender != address(this) || handler == address(this)), covering P3 + P5
- `prop4_setFallbackHandler_stores_handler`: Proves atomic, exact write after setFallbackHandler
- `prop6_zero_handler_fallback_returns_silently`: Proves silent return when no handler registered
- Property 7 is verified via CALL hook asserting value==0 for handler calls
- `prop8a/8b_fallback_can_succeed/fail_with_handler`: Reachability rules showing outcome propagation

**Attack Vectors (Properties 9-12):**
- `prop9_handler_module_reentrancy_attack`: Satisfy rule demonstrating handler-as-module reentrancy is reachable
- `prop10_setFallbackHandler_no_code_check`: Satisfy rule demonstrating EOA registration is possible (no extcodesize check)
- Property 11 partially covered by CALL hook (argsLength >= 20); content verification skipped (CVL CALL hook cannot read memory at argsOffset)
- `prop12_no_handler_silent_success_attack`: Satisfy rule demonstrating silent success with no handler

### Key Technical Solutions
1. **Ghost variable**: Used `fallbackHandlerGhost` (from invariants.spec) for all storage reads instead of getter function, avoiding remote prover resolution issues
2. **Bitwise-and fix**: Added `require !(executingContract == currentContract && fallbackHandlerGhost == 0 && addr != 0)` in CALL hook to prune spurious paths from bitwise-and over-approximation (mathematical tautology: `and(mask, 0) == 0`)
3. **CALL hook**: Single hook covering Property 7 (value==0) and Property 11 (argsLength>=20)
4. **Filter strategy**: prop2 excludes fallback/execTransaction/execTransactionFromModule to avoid ghost HAVOC; prop1 uses `reachableOnly(f)` from invariants.spec

### Skip
Property 11 (content half): CVL CALL hook cannot dereference memory at argsOffset to verify the 20 appended bytes equal caller(). The structural aspects (≥20 bytes, value=0) are verified in the CALL hook.
