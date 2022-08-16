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
	helpers::{
		account_data, create_code_hash, evm_create2_address, evm_create_address,
		get_evm_account_codes, get_evm_account_storages, account_nonce,
	},
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

pub fn test_evm_counter() {
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

	//Hello World contract
	//let smart_contract = "608060405234801561001057600080fd5b506040518060400160405280601181526020017f48614c7c4f6f6f6f6f6f2057656c747e210000000000000000000000000000008152506000908161005591906102ab565b5061037d565b600081519050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b600060028204905060018216806100dc57607f821691505b6020821081036100ef576100ee610095565b5b50919050565b60008190508160005260206000209050919050565b60006020601f8301049050919050565b600082821b905092915050565b6000600883026101577fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8261011a565b610161868361011a565b95508019841693508086168417925050509392505050565b6000819050919050565b6000819050919050565b60006101a86101a361019e84610179565b610183565b610179565b9050919050565b6000819050919050565b6101c28361018d565b6101d66101ce826101af565b848454610127565b825550505050565b600090565b6101eb6101de565b6101f68184846101b9565b505050565b5b8181101561021a5761020f6000826101e3565b6001810190506101fc565b5050565b601f82111561025f57610230816100f5565b6102398461010a565b81016020851015610248578190505b61025c6102548561010a565b8301826101fb565b50505b505050565b600082821c905092915050565b600061028260001984600802610264565b1980831691505092915050565b600061029b8383610271565b9150826002028217905092915050565b6102b48261005b565b67ffffffffffffffff8111156102cd576102cc610066565b5b6102d782546100c4565b6102e282828561021e565b600060209050601f8311600181146103155760008415610303578287015190505b61030d858261028f565b865550610375565b601f198416610323866100f5565b60005b8281101561034b57848901518255600182019150602085019450602081019050610326565b868310156103685784890151610364601f891682610271565b8355505b6001600288020188555050505b505050505050565b6102e88061038c6000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80637c48ee0f1461003b5780639ddbd62b14610059575b600080fd5b610043610077565b6040516100509190610230565b60405180910390f35b610061610105565b60405161006e9190610230565b60405180910390f35b6000805461008490610281565b80601f01602080910402602001604051908101604052809291908181526020018280546100b090610281565b80156100fd5780601f106100d2576101008083540402835291602001916100fd565b820191906000526020600020905b8154815290600101906020018083116100e057829003601f168201915b505050505081565b60606000805461011490610281565b80601f016020809104026020016040519081016040528092919081815260200182805461014090610281565b801561018d5780601f106101625761010080835404028352916020019161018d565b820191906000526020600020905b81548152906001019060200180831161017057829003601f168201915b5050505050905090565b600081519050919050565b600082825260208201905092915050565b60005b838110156101d15780820151818401526020810190506101b6565b838111156101e0576000848401525b50505050565b6000601f19601f8301169050919050565b600061020282610197565b61020c81856101a2565b935061021c8185602086016101b3565b610225816101e6565b840191505092915050565b6000602082019050818103600083015261024a81846101f7565b905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b6000600282049050600182168061029957607f821691505b6020821081036102ac576102ab610252565b5b5091905056fea2646970667358221220bc5cbb383d8494d5e743c1c60efac54ce0600d980dc308b3018a90eed3d419f364736f6c634300080f0033";
	//Counter.sol
	let smart_contract = "608060405234801561001057600080fd5b50600160008190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610377806100696000396000f3fe6080604052600436106100435760003560e01c80631003e2d21461004d57806333cf508014610076578063371303c0146100a157806358992216146100b857610044565b5b60056000819055005b34801561005957600080fd5b50610074600480360381019061006f9190610209565b6100e3565b005b34801561008257600080fd5b5061008b61013f565b6040516100989190610245565b60405180910390f35b3480156100ad57600080fd5b506100b6610148565b005b3480156100c457600080fd5b506100cd6101a4565b6040516100da91906102a1565b60405180910390f35b806000808282546100f491906102eb565b9250508190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b60008054905090565b600160008082825461015a91906102eb565b9250508190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550565b6000600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b600080fd5b6000819050919050565b6101e6816101d3565b81146101f157600080fd5b50565b600081359050610203816101dd565b92915050565b60006020828403121561021f5761021e6101ce565b5b600061022d848285016101f4565b91505092915050565b61023f816101d3565b82525050565b600060208201905061025a6000830184610236565b92915050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061028b82610260565b9050919050565b61029b81610280565b82525050565b60006020820190506102b66000830184610292565b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b60006102f6826101d3565b9150610301836101d3565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03821115610336576103356102bc565b5b82820190509291505056fea2646970667358221220b37e993e133ed19c840809cc8acbbba8116dee3744ba01c81044d75146805c9364736f6c634300080f0033";

	let trusted_call = TrustedCall::evm_create(
		sender_acc.clone(),
		sender_evm_acc,
		Vec::from_hex(smart_contract.to_string()).unwrap(),
		U256::from(0),
		10_000_000,    // gas limit
		U256::from(1), // max_fee_per_gas !>= min_gas_price defined in runtime
		None,
		Some(U256::from(0)),
		Vec::new(),
	)
	.sign(&sender.clone().into(), 0, &mrenclave, &shard);

	// when
	let execution_address = state.execute_with(|| evm_create_address(sender_evm_acc, 0));
	Stf::execute(&mut state, trusted_call, &mut opaque_vec).unwrap();

	// then
	assert_eq!(
		execution_address,
		H160::from_slice(
			&Vec::from_hex("0xce2c9e7f9c10049996173b2ca2d9a6815a70e890".to_string()).unwrap(),
		)
	);

	assert!(state.execute_with(|| get_evm_account_codes(&execution_address).is_some()));

	let counter_value = state
		.execute_with(|| get_evm_account_storages(&execution_address, &H256::zero()))
		.unwrap();
	assert_eq!(H256::from_low_u64_be(1), counter_value);
	let last_caller = state
		.execute_with(|| get_evm_account_storages(&execution_address, &H256::from_low_u64_be(1)))
		.unwrap();
	assert_eq!(H256::from(sender_evm_acc), last_caller);

	// Call to inc() function
	{
		// in solidity compile information you get the hash of the call
		let function_hash = Vec::from_hex("371303c0".to_string()).unwrap();

		let inc_call = TrustedCall::evm_call(
			sender_acc.clone(),
			sender_evm_acc,
			execution_address,
			function_hash,
			U256::from(0),
			10_000_000,    // gas limit
			U256::from(1), // max_fee_per_gas !>= min_gas_price defined in runtime
			None,
			Some(U256::from(1)),
			Vec::new(),
		)
		.sign(&sender.clone().into(), 1, &mrenclave, &shard);
		Stf::execute(&mut state, inc_call, &mut opaque_vec).unwrap();

		let counter_value = state
			.execute_with(|| get_evm_account_storages(&execution_address, &H256::zero()))
			.unwrap();
		assert_eq!(counter_value, H256::from_low_u64_be(2));
	}

	// Call the fallback function
	{
		let inc_call = TrustedCall::evm_call(
			sender_acc.clone(),
			sender_evm_acc,
			execution_address,
			Vec::new(), // Empty input calls the fallback function
			U256::from(0),
			10_000_000,    // gas limit
			U256::from(1), // max_fee_per_gas !>= min_gas_price defined in runtime
			None,
			Some(U256::from(2)),
			Vec::new(),
		)
		.sign(&sender.clone().into(), 2, &mrenclave, &shard);
		Stf::execute(&mut state, inc_call, &mut opaque_vec).unwrap();

		let counter_value = state
			.execute_with(|| get_evm_account_storages(&execution_address, &H256::zero()))
			.unwrap();
		assert_eq!(counter_value, H256::from_low_u64_be(5));
	}

	// Call to inc() function
	{
		// in solidity compile information you get the hash of the call
		let function_hash = Vec::from_hex("371303c0".to_string()).unwrap();

		let inc_call = TrustedCall::evm_call(
			sender_acc.clone(),
			sender_evm_acc,
			execution_address,
			function_hash,
			U256::from(0),
			10_000_000,    // gas limit
			U256::from(1), // max_fee_per_gas !>= min_gas_price defined in runtime
			None,
			Some(U256::from(3)),
			Vec::new(),
		)
		.sign(&sender.clone().into(), 3, &mrenclave, &shard);
		Stf::execute(&mut state, inc_call, &mut opaque_vec).unwrap();

		let counter_value = state
			.execute_with(|| get_evm_account_storages(&execution_address, &H256::zero()))
			.unwrap();
		assert_eq!(counter_value, H256::from_low_u64_be(6));
	}

	// Call to add() function
	{
		// in solidity compile information you get the hash of the call
		let function_hash = "1003e2d2";
		// 32 byte string of the value to add in hex
		let add_value = "0000000000000000000000000000000000000000000000000000000000000002";
		let function_input = Vec::from_hex(format!("{}{}", function_hash, add_value)).unwrap();

		let inc_call = TrustedCall::evm_call(
			sender_acc.clone(),
			sender_evm_acc,
			execution_address,
			function_input,
			U256::from(0),
			10_000_000,    // gas limit
			U256::from(1), // max_fee_per_gas !>= min_gas_price defined in runtime
			None,
			Some(U256::from(4)),
			Vec::new(),
		)
		.sign(&sender.clone().into(), 4, &mrenclave, &shard);
		Stf::execute(&mut state, inc_call, &mut opaque_vec).unwrap();

		let counter_value = state
			.execute_with(|| get_evm_account_storages(&execution_address, &H256::zero()))
			.unwrap();
		assert_eq!(counter_value, H256::from_low_u64_be(8));
	}
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
	endow(&mut state, vec![(sender_evm_substrate_addr.clone(), 51_777_000_000_000, 0)]);

	let smart_contract = "608060405234801561001057600080fd5b50600160008190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610377806100696000396000f3fe6080604052600436106100435760003560e01c80631003e2d21461004d57806333cf508014610076578063371303c0146100a157806358992216146100b857610044565b5b60056000819055005b34801561005957600080fd5b50610074600480360381019061006f9190610209565b6100e3565b005b34801561008257600080fd5b5061008b61013f565b6040516100989190610245565b60405180910390f35b3480156100ad57600080fd5b506100b6610148565b005b3480156100c457600080fd5b506100cd6101a4565b6040516100da91906102a1565b60405180910390f35b806000808282546100f491906102eb565b9250508190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b60008054905090565b600160008082825461015a91906102eb565b9250508190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550565b6000600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b600080fd5b6000819050919050565b6101e6816101d3565b81146101f157600080fd5b50565b600081359050610203816101dd565b92915050565b60006020828403121561021f5761021e6101ce565b5b600061022d848285016101f4565b91505092915050565b61023f816101d3565b82525050565b600060208201905061025a6000830184610236565b92915050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061028b82610260565b9050919050565b61029b81610280565b82525050565b60006020820190506102b66000830184610292565b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b60006102f6826101d3565b9150610301836101d3565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03821115610336576103356102bc565b5b82820190509291505056fea2646970667358221220b37e993e133ed19c840809cc8acbbba8116dee3744ba01c81044d75146805c9364736f6c634300080f0033";
	let smart_contract = Vec::from_hex(smart_contract.to_string()).unwrap();

	let trusted_call = TrustedCall::evm_create(
		sender_acc.clone(),
		sender_evm_acc,
		smart_contract.clone(),
		U256::from(0), // value
		10_000_000,    // gas limit
		U256::from(1), // max_fee_per_gas !>= min_gas_price defined in runtime
		None,
		Some(U256::from(0)),
		Vec::new(),
	)
	.sign(&sender.clone().into(), 0, &mrenclave, &shard);

	// Should be the first call of the evm account
	let nonce = state.execute_with(|| account_nonce(&sender_evm_substrate_addr));
	assert_eq!(nonce, 0);
	let execution_address = evm_create_address(sender_evm_acc, nonce);
	Stf::execute(&mut state, trusted_call, &mut opaque_vec).unwrap();

	assert_eq!(
		execution_address,
		H160::from_slice(
			&Vec::from_hex("0xce2c9e7f9c10049996173b2ca2d9a6815a70e890".to_string()).unwrap(),
		)
	);
	assert!(state.execute_with(|| get_evm_account_codes(&execution_address).is_some()));

	// Ensure the nonce of the evm account has been increased by one
	// Should be the first call of the evm account
	let nonce = state.execute_with(|| account_nonce(&sender_evm_substrate_addr));
	assert_eq!(nonce, 1);
}

pub fn test_evm_create2() {
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

	let salt = H256::from_low_u64_be(20);
	let smart_contract = "608060405234801561001057600080fd5b50600160008190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610377806100696000396000f3fe6080604052600436106100435760003560e01c80631003e2d21461004d57806333cf508014610076578063371303c0146100a157806358992216146100b857610044565b5b60056000819055005b34801561005957600080fd5b50610074600480360381019061006f9190610209565b6100e3565b005b34801561008257600080fd5b5061008b61013f565b6040516100989190610245565b60405180910390f35b3480156100ad57600080fd5b506100b6610148565b005b3480156100c457600080fd5b506100cd6101a4565b6040516100da91906102a1565b60405180910390f35b806000808282546100f491906102eb565b9250508190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b60008054905090565b600160008082825461015a91906102eb565b9250508190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550565b6000600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b600080fd5b6000819050919050565b6101e6816101d3565b81146101f157600080fd5b50565b600081359050610203816101dd565b92915050565b60006020828403121561021f5761021e6101ce565b5b600061022d848285016101f4565b91505092915050565b61023f816101d3565b82525050565b600060208201905061025a6000830184610236565b92915050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061028b82610260565b9050919050565b61029b81610280565b82525050565b60006020820190506102b66000830184610292565b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b60006102f6826101d3565b9150610301836101d3565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03821115610336576103356102bc565b5b82820190509291505056fea2646970667358221220b37e993e133ed19c840809cc8acbbba8116dee3744ba01c81044d75146805c9364736f6c634300080f0033";
	let smart_contract = Vec::from_hex(smart_contract.to_string()).unwrap();

	let trusted_call = TrustedCall::evm_create2(
		sender_acc.clone(),
		sender_evm_acc,
		smart_contract.clone(),
		salt,
		U256::from(0), // value
		10_000_000,    // gas limit
		U256::from(1), // max_fee_per_gas !>= min_gas_price defined in runtime
		None,
		Some(U256::from(0)),
		Vec::new(),
	)
	.sign(&sender.clone().into(), 0, &mrenclave, &shard);

	// when
	let code_hash = create_code_hash(&smart_contract);
	let execution_address =
		state.execute_with(|| evm_create2_address(sender_evm_acc, salt, code_hash));
	Stf::execute(&mut state, trusted_call, &mut opaque_vec).unwrap();

	// then
	assert_eq!(
		execution_address,
		H160::from_slice(
			&Vec::from_hex("0xe07ad7925f6b2b10c5a7653fb16db7a984059d11".to_string()).unwrap(),
		)
	);

	assert!(state.execute_with(|| get_evm_account_codes(&execution_address).is_some()));
}
