use core::hash::HashStateTrait;
/// Address seed computation for deterministic wallet addresses.
/// address_seed = Poseidon(issuer, sub, salt)
///
/// The address_seed uniquely identifies a wallet owner based on their
/// OAuth issuer + `sub` claim pair and a salt value.

use core::poseidon::PoseidonTrait;

/// Compute the address seed from a user's OAuth issuer, `sub` claim and salt.
pub fn compute_address_seed(issuer: felt252, sub: felt252, salt: felt252) -> felt252 {
    PoseidonTrait::new().update(issuer).update(sub).update(salt).finalize()
}

/// Verify that an address seed matches the expected value.
pub fn verify_address_seed(
    address_seed: felt252, issuer: felt252, sub: felt252, salt: felt252,
) -> bool {
    let expected = compute_address_seed(issuer, sub, salt);
    address_seed == expected
}
