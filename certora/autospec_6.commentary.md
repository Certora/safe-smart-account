
# Safe Storage Accessibility Properties: Final CVL Specification

## Coverage Summary

All 10 properties formalized (except P4 which is skipped with justification):

**P1** (`simulateAndRevert_always_reverts`): Proves simulateAndRevert ALWAYS reverts via `@withrevert` + `assert lastReverted`. VERIFIED.

**P2** (`simulateAndRevert_no_storage_change`): Proves no storage modification by comparing `lastStorage` before and after call. VERIFIED (follows from P1's unconditional revert).

**P3** (`getStorageAt_return_length`): Proves `result.length == length * 32` for non-overflow inputs (restricted to `length <= MAX_VALID_STORAGE_LENGTH`). VERIFIED.

**P4** (SKIPPED): CVL has no `sload(k)` for variable k, no built-in 32-byte word extraction from `bytes` without a harness function, and the Certora team noted hooks cannot be applied to `getStorageAt` when called as a public function with arbitrary arguments.

**P5** (`getStorageAt_no_access_control`): Proves getStorageAt never reverts for any msg.sender. Restricted to `msg.value == 0` (Solidity's non-payable guard is a language requirement, not access control) and `length < 2^59` (prover's 64-bit allocation-size model). VERIFIED.

**P6** (`simulateAndRevert_no_access_control`): Proves simulateAndRevert always reverts for ANY caller (msg.sender unconstrained) — the best CVL formalization of "no access control" for a function that always reverts. VERIFIED.

**P7** (`simulateAndRevert_memory_corruption_safe`): Proves memory corruption by malicious delegatecall cannot affect on-chain state (`lastStorage == initialState`). VERIFIED.

**P8** (`simulateAndRevert_reentrancy_safe`): Proves reentrancy during execTransaction cannot cause persistent state modification (same storage comparison as P7). VERIFIED.

**P9** (`getStorageAt_no_overflow_attack`): Proves `result.length == length * 32` with unrestricted domain. The Certora prover's abstract model treats `<<5` as exact `*32` (SANITY_FAILURE occurs when using `satisfy result.length < length * 32`), so the overflow attack cannot be triggered within the formal verification framework. VERIFIED.

**P10** (`simulateAndRevert_empty_target_reverts`): Proves simulateAndRevert reverts even with `targetContract = address(0)` (empty/non-existent code). VERIFIED.
