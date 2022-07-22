/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0


	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

use crate::test::tests_main::test_setup;
use core::str::FromStr;
use ita_stf::{
	helpers::{account_data, get_evm_account_codes, get_evm_account_storages},
	test_genesis::{endow, endowed_account as funded_pair},
	Stf, TrustedCall,
};
use itp_types::AccountId;
use primitive_types::H256;
use sgx_externalities::SgxExternalitiesTrait;
use sgx_runtime::AddressMapping;
use sp_core::{crypto::Pair, H160, U256};
use std::{string::ToString, vec::Vec};
use substrate_api_client::utils::FromHexString;

pub fn test_evm_call() {
	// given
	let (_, mut state, shard, mrenclave, _, _) = test_setup();
	let mut opaque_vec = Vec::new();

	// Create the sender account.
	let sender = funded_pair();
	let sender_acc: AccountId = sender.public().into();
	let mut sender_evm_acc_slice: [u8; 20] = [0; 20];
	sender_evm_acc_slice
		.copy_from_slice((<[u8; 32]>::from(sender_acc.clone())).get(0..20).unwrap());
	let sender_evm_acc: H160 = sender_evm_acc_slice.into();
	// Ensure the substrate version of the evm account has some money.
	let sender_evm_substrate_addr =
		sgx_runtime::HashedAddressMapping::into_account_id(sender_evm_acc);
	endow(&mut state, vec![(sender_evm_substrate_addr, 51_777_000_000_000, 0)]);

	// Create the receiver account.
	let destination_evm_acc = H160::from_str("1000000000000000000000000000000000000001").unwrap();
	let destination_evm_substrate_addr =
		sgx_runtime::HashedAddressMapping::into_account_id(destination_evm_acc);
	assert!(state.execute_with(|| account_data(&destination_evm_substrate_addr).is_none()));

	let transfer_value: u128 = 1_000_000_000;

	let trusted_call = TrustedCall::evm_call(
		sender_acc,
		sender_evm_acc,
		destination_evm_acc,
		Vec::new(),
		U256::from(transfer_value),
		21776, // gas limit
		U256::from(1_000_000_000),
		None,
		Some(U256::from(0)),
		Vec::new(),
	)
	.sign(&sender.clone().into(), 0, &mrenclave, &shard);

	// when
	Stf::execute(&mut state, trusted_call, &mut opaque_vec).unwrap();

	// then
	assert_eq!(
		transfer_value,
		state.execute_with(|| account_data(&destination_evm_substrate_addr).unwrap().free)
	);
}

pub fn test_evm_create() {
	// given
	let (_, mut state, shard, mrenclave, _, _) = test_setup();
	let mut opaque_vec = Vec::new();

	// Create the sender account.
	let sender = funded_pair();
	let sender_acc: AccountId = sender.public().into();
	let mut sender_evm_acc_slice: [u8; 20] = [0; 20];
	sender_evm_acc_slice
		.copy_from_slice((<[u8; 32]>::from(sender_acc.clone())).get(0..20).unwrap());
	let sender_evm_acc: H160 = sender_evm_acc_slice.into();
	// Ensure the substrate version of the evm account has some money.
	let sender_evm_substrate_addr =
		sgx_runtime::HashedAddressMapping::into_account_id(sender_evm_acc);
	endow(&mut state, vec![(sender_evm_substrate_addr, 51_777_000_000_000, 0)]);

	let smart_contract = "608060405234801561001057600080fd5b506040518060400160405280601181526020017f48614c7c4f6f6f6f6f6f2057656c747e210000000000000000000000000000008152506000908161005591906102ab565b5061037d565b600081519050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b600060028204905060018216806100dc57607f821691505b6020821081036100ef576100ee610095565b5b50919050565b60008190508160005260206000209050919050565b60006020601f8301049050919050565b600082821b905092915050565b6000600883026101577fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8261011a565b610161868361011a565b95508019841693508086168417925050509392505050565b6000819050919050565b6000819050919050565b60006101a86101a361019e84610179565b610183565b610179565b9050919050565b6000819050919050565b6101c28361018d565b6101d66101ce826101af565b848454610127565b825550505050565b600090565b6101eb6101de565b6101f68184846101b9565b505050565b5b8181101561021a5761020f6000826101e3565b6001810190506101fc565b5050565b601f82111561025f57610230816100f5565b6102398461010a565b81016020851015610248578190505b61025c6102548561010a565b8301826101fb565b50505b505050565b600082821c905092915050565b600061028260001984600802610264565b1980831691505092915050565b600061029b8383610271565b9150826002028217905092915050565b6102b48261005b565b67ffffffffffffffff8111156102cd576102cc610066565b5b6102d782546100c4565b6102e282828561021e565b600060209050601f8311600181146103155760008415610303578287015190505b61030d858261028f565b865550610375565b601f198416610323866100f5565b60005b8281101561034b57848901518255600182019150602085019450602081019050610326565b868310156103685784890151610364601f891682610271565b8355505b6001600288020188555050505b505050505050565b6102e88061038c6000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80637c48ee0f1461003b5780639ddbd62b14610059575b600080fd5b610043610077565b6040516100509190610230565b60405180910390f35b610061610105565b60405161006e9190610230565b60405180910390f35b6000805461008490610281565b80601f01602080910402602001604051908101604052809291908181526020018280546100b090610281565b80156100fd5780601f106100d2576101008083540402835291602001916100fd565b820191906000526020600020905b8154815290600101906020018083116100e057829003601f168201915b505050505081565b60606000805461011490610281565b80601f016020809104026020016040519081016040528092919081815260200182805461014090610281565b801561018d5780601f106101625761010080835404028352916020019161018d565b820191906000526020600020905b81548152906001019060200180831161017057829003601f168201915b5050505050905090565b600081519050919050565b600082825260208201905092915050565b60005b838110156101d15780820151818401526020810190506101b6565b838111156101e0576000848401525b50505050565b6000601f19601f8301169050919050565b600061020282610197565b61020c81856101a2565b935061021c8185602086016101b3565b610225816101e6565b840191505092915050565b6000602082019050818103600083015261024a81846101f7565b905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b6000600282049050600182168061029957607f821691505b6020821081036102ac576102ab610252565b5b5091905056fea2646970667358221220bc5cbb383d8494d5e743c1c60efac54ce0600d980dc308b3018a90eed3d419f364736f6c634300080f0033";

	let trusted_call = TrustedCall::evm_create(
		sender_acc.clone(),
		sender_evm_acc,
		Vec::from_hex(smart_contract.to_string()).unwrap(),
		U256::from(0),
		42949695,      // gas limit
		U256::from(1), // max_fee_per_gas !>= min_gas_price defined in runtime
		None,
		Some(U256::from(0)),
		Vec::new(),
	)
	.sign(&sender.clone().into(), 0, &mrenclave, &shard);

	// when
	Stf::execute(&mut state, trusted_call, &mut opaque_vec).unwrap();

	// then
	let execution_adress = H160::from_slice(
		&Vec::from_hex("0xce2c9e7f9c10049996173b2ca2d9a6815a70e890".to_string()).unwrap(),
	);

	assert!(state.execute_with(|| get_evm_account_codes(&execution_adress).is_some()));
	assert!(state.execute_with(|| get_evm_account_codes(&sender_evm_acc).is_none()));

	// in solidity compile information you get the hash of the call
	let functionhash = Vec::from_hex("9ddbd62b".to_string()).unwrap();

	let trusted_call_call = TrustedCall::evm_call(
		sender_acc,
		sender_evm_acc,
		execution_adress,
		functionhash,
		U256::from(0),
		1_000,         // gas limit
		U256::from(1), // max_fee_per_gas !>= min_gas_price defined in runtime
		None,
		Some(U256::from(1)),
		Vec::new(),
	)
	.sign(&sender.clone().into(), 1, &mrenclave, &shard);

	Stf::execute(&mut state, trusted_call_call, &mut opaque_vec).unwrap();

	let h256 = state
		.execute_with(|| get_evm_account_storages(&execution_adress, &H256::zero()))
		.unwrap();
	assert_ne!(h256, H256::zero()); // What a test!
}
