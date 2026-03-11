/// JWKS Registry Contract
/// Stores Google/Apple RSA public keys on-chain for JWT verification.
/// Admin-managed: keys are updated when providers rotate their JWKS.
/// Validates RSA signatures for Google/Apple OIDC.

use starknet::ContractAddress;

/// RSA public key stored on-chain.
/// The modulus `n` is a 2048-bit RSA key stored as 24 × u96 limbs (little-endian),
/// matching Garaga's RSA2048Chunks format (6 × u384, each u384 = 4 × u96).
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct JWKSKey {
    /// RSA modulus as 24 × u96 limbs (little-endian, Garaga-compatible)
    pub n0: felt252,
    pub n1: felt252,
    pub n2: felt252,
    pub n3: felt252,
    pub n4: felt252,
    pub n5: felt252,
    pub n6: felt252,
    pub n7: felt252,
    pub n8: felt252,
    pub n9: felt252,
    pub n10: felt252,
    pub n11: felt252,
    pub n12: felt252,
    pub n13: felt252,
    pub n14: felt252,
    pub n15: felt252,
    pub n16: felt252,
    pub n17: felt252,
    pub n18: felt252,
    pub n19: felt252,
    pub n20: felt252,
    pub n21: felt252,
    pub n22: felt252,
    pub n23: felt252,
    /// Provider identifier (hash of 'google' or 'apple')
    pub provider: felt252,
    /// Expiry timestamp (0 = no expiry)
    pub valid_until: u64,
    /// Whether this key is active
    pub is_active: bool,
}

#[starknet::interface]
pub trait IJWKSRegistry<TContractState> {
    /// Set or update an RSA key. Admin only.
    fn set_key(ref self: TContractState, kid: felt252, key: JWKSKey);
    /// Remove (deactivate) a key. Admin only.
    fn remove_key(ref self: TContractState, kid: felt252);
    /// Get a key by its kid.
    fn get_key(self: @TContractState, kid: felt252) -> JWKSKey;
    /// Check if a key is valid (exists, active, not expired).
    fn is_key_valid(self: @TContractState, kid: felt252) -> bool;
    /// Get a key by its kid, asserting it is valid. Saves one external call vs
    /// is_key_valid+get_key.
    fn get_key_if_valid(self: @TContractState, kid: felt252) -> JWKSKey;
    /// Transfer admin to a new address. Admin only.
    fn transfer_admin(ref self: TContractState, new_admin: ContractAddress);
    /// Get current admin address.
    fn get_admin(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod JWKSRegistry {
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_block_timestamp, get_caller_address};
    use super::{IJWKSRegistry, JWKSKey};

    #[storage]
    struct Storage {
        admin: ContractAddress,
        keys: Map<felt252, JWKSKey>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        KeySet: KeySet,
        KeyRemoved: KeyRemoved,
        AdminTransferred: AdminTransferred,
        DummyEvent: DummyEvent,
    }

    #[derive(Drop, starknet::Event)]
    struct DummyEvent {
        x: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct KeySet {
        kid: felt252,
        provider: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct KeyRemoved {
        kid: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct AdminTransferred {
        old_admin: ContractAddress,
        new_admin: ContractAddress,
    }

    #[constructor]
    fn constructor(ref self: ContractState, admin: ContractAddress) {
        self.admin.write(admin);
    }

    #[abi(embed_v0)]
    impl JWKSRegistryImpl of IJWKSRegistry<ContractState> {
        fn set_key(ref self: ContractState, kid: felt252, key: JWKSKey) {
            self.assert_admin();
            self.keys.write(kid, key);
            self.emit(KeySet { kid, provider: key.provider });
        }

        fn remove_key(ref self: ContractState, kid: felt252) {
            self.assert_admin();
            let mut key = self.keys.read(kid);
            key.is_active = false;
            self.keys.write(kid, key);
            self.emit(KeyRemoved { kid });
        }

        fn get_key(self: @ContractState, kid: felt252) -> JWKSKey {
            self.keys.read(kid)
        }

        fn is_key_valid(self: @ContractState, kid: felt252) -> bool {
            let key = self.keys.read(kid);
            if !key.is_active {
                return false;
            }
            if key.valid_until != 0 {
                let now = get_block_timestamp();
                if now > key.valid_until {
                    return false;
                }
            }
            true
        }

        fn get_key_if_valid(self: @ContractState, kid: felt252) -> JWKSKey {
            let key = self.keys.read(kid);
            assert!(key.is_active, "JWKS key invalid or expired");
            if key.valid_until != 0 {
                assert!(get_block_timestamp() <= key.valid_until, "JWKS key invalid or expired");
            }
            key
        }

        fn transfer_admin(ref self: ContractState, new_admin: ContractAddress) {
            self.assert_admin();
            let old_admin = self.admin.read();
            self.admin.write(new_admin);
            self.emit(AdminTransferred { old_admin, new_admin });
        }

        fn get_admin(self: @ContractState) -> ContractAddress {
            self.admin.read()
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn assert_admin(self: @ContractState) {
            let caller = get_caller_address();
            let admin = self.admin.read();
            assert!(caller == admin, "Only admin can call this function");
        }
    }
}
