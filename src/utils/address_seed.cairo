use core::hash::HashStateTrait;
/// Address seed computation for deterministic wallet addresses.
/// address_seed = Poseidon(sub, salt)
///
/// The address_seed uniquely identifies a wallet owner based on their
/// OAuth `sub` claim and a salt value. Same Google account = same wallet.

use core::poseidon::PoseidonTrait;

/// Compute the address seed from a user's OAuth `sub` claim and salt.
pub fn compute_address_seed(sub: felt252, salt: felt252) -> felt252 {
    PoseidonTrait::new().update(sub).update(salt).finalize()
}

/// Verify that an address seed matches the expected value.
pub fn verify_address_seed(address_seed: felt252, sub: felt252, salt: felt252) -> bool {
    let expected = compute_address_seed(sub, salt);
    address_seed == expected
}
