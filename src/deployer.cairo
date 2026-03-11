use starknet::ContractAddress;

#[starknet::interface]
pub trait IOAuthAccountDeployer<TContractState> {
    /// Deploy an OAuth account with an initial session registered.
    /// Requires full JWT signature for on-chain RSA verification.
    fn deploy_oauth_account_with_session(
        ref self: TContractState,
        class_hash: starknet::ClassHash,
        salt: felt252,
        address_seed: felt252,
        jwks_registry: ContractAddress,
        ephemeral_pubkey: felt252,
        nonce: felt252,
        max_block: u64,
        renewal_deadline: u64,
        signature: Span<felt252>,
    ) -> ContractAddress;

    /// Register a new session on an existing account (fallback when grace period expired).
    /// Used when the user's session AND renewal period expire and they re-authenticate.
    /// Requires full JWT signature for on-chain RSA verification.
    fn register_session(
        ref self: TContractState,
        account_address: ContractAddress,
        ephemeral_pubkey: felt252,
        nonce: felt252,
        max_block: u64,
        renewal_deadline: u64,
        signature: Span<felt252>,
    );

    /// Legacy: Deploy an OAuth account without a session (for backwards compatibility).
    fn deploy_oauth_account(
        self: @TContractState,
        class_hash: starknet::ClassHash,
        salt: felt252,
        address_seed: felt252,
        jwks_registry: ContractAddress,
    ) -> ContractAddress;

    fn get_version(self: @TContractState) -> u8;
}

#[starknet::contract]
pub mod OAuthAccountDeployer {
    use starknet::syscalls::deploy_syscall;
    use starknet::{ClassHash, ContractAddress, SyscallResultTrait, get_contract_address};

    // Interface for calling register_session_from_deployer on the deployed account
    #[starknet::interface]
    trait IOAuthAccountSession<TContractState> {
        fn register_session_from_deployer(
            ref self: TContractState,
            ephemeral_pubkey: felt252,
            nonce: felt252,
            max_block: u64,
            renewal_deadline: u64,
            signature: Span<felt252>,
        );
    }

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl OAuthAccountDeployerImpl of super::IOAuthAccountDeployer<ContractState> {
        /// Deploy an OAuth account and register the initial session in one transaction.
        /// Requires full JWT signature for on-chain RSA verification.
        fn deploy_oauth_account_with_session(
            ref self: ContractState,
            class_hash: ClassHash,
            salt: felt252,
            address_seed: felt252,
            jwks_registry: ContractAddress,
            ephemeral_pubkey: felt252,
            nonce: felt252,
            max_block: u64,
            renewal_deadline: u64,
            signature: Span<felt252>,
        ) -> ContractAddress {
            // Get deployer address (this contract) to pass to the account
            let deployer_address = get_contract_address();

            // Deploy the account with deployer address in constructor
            let mut constructor_calldata = array![
                address_seed, jwks_registry.into(), deployer_address.into(),
            ];
            let (contract_address, _) = deploy_syscall(
                class_hash, salt, constructor_calldata.span(), true,
            )
                .unwrap_syscall();

            // Register the initial session on the newly deployed account
            // The account will perform full RSA verification on the signature
            let account = IOAuthAccountSessionDispatcher { contract_address };
            account
                .register_session_from_deployer(
                    ephemeral_pubkey, nonce, max_block, renewal_deadline, signature,
                );

            contract_address
        }

        /// Register a new session on an existing account (fallback).
        /// Used when user's session AND grace period have expired.
        /// Requires full JWT signature for on-chain RSA verification.
        fn register_session(
            ref self: ContractState,
            account_address: ContractAddress,
            ephemeral_pubkey: felt252,
            nonce: felt252,
            max_block: u64,
            renewal_deadline: u64,
            signature: Span<felt252>,
        ) {
            let account = IOAuthAccountSessionDispatcher { contract_address: account_address };
            account
                .register_session_from_deployer(
                    ephemeral_pubkey, nonce, max_block, renewal_deadline, signature,
                );
        }

        /// Legacy deployment without session (for backwards compatibility).
        /// The account will need to register a session separately (expensive).
        fn deploy_oauth_account(
            self: @ContractState,
            class_hash: ClassHash,
            salt: felt252,
            address_seed: felt252,
            jwks_registry: ContractAddress,
        ) -> ContractAddress {
            let deployer_address = get_contract_address();
            let mut constructor_calldata = array![
                address_seed, jwks_registry.into(), deployer_address.into(),
            ];
            let (contract_address, _) = deploy_syscall(
                class_hash, salt, constructor_calldata.span(), true,
            )
                .unwrap_syscall();

            contract_address
        }

        fn get_version(self: @ContractState) -> u8 {
            1
        }
    }
}
