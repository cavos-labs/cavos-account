use core::hash::HashStateTrait;
/// Nonce verification for OAuth wallet sessions.
/// The nonce ties an ephemeral key to a JWT, preventing replay attacks.
///
/// nonce = Poseidon(eph_pubkey_lo, eph_pubkey_hi, max_block, randomness)
///
/// Where:
/// - eph_pubkey_lo: lower 128 bits of the ephemeral Stark public key
/// - eph_pubkey_hi: upper 128 bits of the ephemeral Stark public key
/// - max_block: maximum block number this session is valid until
/// - randomness: random value for uniqueness

use core::poseidon::PoseidonTrait;

/// Compute the expected nonce from session parameters.
pub fn compute_nonce(
    eph_pubkey_lo: felt252, eph_pubkey_hi: felt252, max_block: felt252, randomness: felt252,
) -> felt252 {
    PoseidonTrait::new()
        .update(eph_pubkey_lo)
        .update(eph_pubkey_hi)
        .update(max_block)
        .update(randomness)
        .finalize()
}

/// Verify that a nonce matches the expected value from session parameters.
pub fn verify_nonce(
    nonce: felt252,
    eph_pubkey_lo: felt252,
    eph_pubkey_hi: felt252,
    max_block: felt252,
    randomness: felt252,
) -> bool {
    let expected = compute_nonce(eph_pubkey_lo, eph_pubkey_hi, max_block, randomness);
    nonce == expected
}
