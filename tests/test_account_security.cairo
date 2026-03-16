#[cfg(test)]
mod tests {
    use cavos::cavos_account::{ICavosAccountDispatcher, ICavosAccountDispatcherTrait};
    use snforge_std::{
        ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address, test_address,
    };
    use starknet::ContractAddress;

    fn deploy_account() -> ContractAddress {
        let class = declare("CavosAccount").unwrap().contract_class();
        let jwks_registry: ContractAddress = 0x123.try_into().unwrap();
        let constructor_calldata = array![
            0x1234, // address_seed
            jwks_registry.into(), // jwks_registry (unused by these tests)
        ];
        let (contract_address, _) = class.deploy(@constructor_calldata).unwrap();
        contract_address
    }

    #[test]
    #[should_panic]
    fn test_emergency_revoke_requires_authenticated_owner() {
        let account_address = deploy_account();
        let dispatcher = ICavosAccountDispatcher { contract_address: account_address };

        start_cheat_caller_address(account_address, test_address());
        dispatcher.emergency_revoke();
    }

    #[test]
    #[should_panic]
    fn test_revoke_session_requires_authenticated_owner() {
        let account_address = deploy_account();
        let dispatcher = ICavosAccountDispatcher { contract_address: account_address };

        start_cheat_caller_address(account_address, test_address());
        dispatcher.revoke_session(0xdeadbeef);
    }
}
