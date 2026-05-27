Successfully formalized all 12 properties for the Safe contract's signature verification and hash management component.

## Summary of Properties

### Properties 1-8 (Goal: demonstrate holds) - All VERIFIED:

1. **threshold_bounds_valid** (invariant): After initialization, 1 <= threshold <= ownerCount. Uses requireInvariant from imported invariants.spec.

2. **approveHash_reverts_for_non_owner**: approveHash must revert when msg.sender is not a registered owner (excluding SENTINEL corner case).

3. **approvedHashes_modified_only_by_owner_approveHash**: Parametric rule ensuring approvedHashes entries can only be written by approveHash called by that entry's owner.

4. **checkSignatures_delegates_with_threshold**: checkSignatures is equivalent to checkNSignatures with the stored threshold.

5. **checkNSignatures_owner_validity_n1/n2**: All owners validated by checkNSignatures must satisfy isOwner.

6. **checkNSignatures_owners_strictly_increasing**: Owner addresses in checkNSignatures are strictly ascending (prevents duplicate counting).

7. **checkNSignatures_v1_requires_executor_or_preapproval**: v=1 pre-approval slots require executor==owner OR approvedHashes[owner][hash] != 0.

8. **domainSeparator_binds_to_contract_address**: domainSeparator() produces different values for different contract addresses (keccak injectivity).

### Properties 9-12 (Attack vectors) - Attacks confirmed via violation:

9. **checkNSignatures_zero_must_revert**: VIOLATED (attack confirmed) - checkNSignatures(n=0) succeeds without verifying any signatures.

10. **legacy_overload_executor_bypass**: VIOLATED (attack confirmed) - Owner as executor satisfies own v=1 slot without prior approveHash.

11. **checkNSignatures_v0_unique_offsets**: VERIFIED - Two v=0 entries with identical s-offsets cannot both succeed in our model (structural constraints prevent the attack).

12. **p256_owner_can_always_sign**: VIOLATED (attack confirmed) - P256 precompile unavailability breaks v=2 signature verification.

## Key Technical Decisions

- Used position-based ghost mappings for signatureSplit to avoid bytes-key hashing issues
- Used `require_uint160(require_uint256(sigR[pos]))` to extract owner address from bytes32
- CONSTANT summary for p256Verify covers both precompile present/absent scenarios
- NONDET for checkContractSignature (inherited from Safe_base_summaries.spec)
- Filtered execTransaction and getTransactionHash from property 3 to avoid false positives
