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

use crate::test::fixtures::test_setup::{test_setup, TestStf};
use core::str::FromStr;
use ita_sgx_runtime::{AddressMapping, HashedAddressMapping, Index, System};
use ita_stf::{
	evm_helpers::{
		create_code_hash, evm_create2_address, evm_create_address, get_evm_account_codes,
		get_evm_account_storages,
	},
	test_genesis::{endow, endowed_account as funded_pair},
	State, TrustedCall,
};
use itp_node_api::metadata::{metadata_mocks::NodeMetadataMock, provider::NodeMetadataRepository};
use itp_sgx_externalities::SgxExternalitiesTrait;
use itp_stf_interface::StateCallInterface;
use itp_stf_primitives::types::KeyPair;
use itp_types::{AccountId, OpaqueCall, ShardIdentifier};
use primitive_types::H256;
use sp_core::{crypto::Pair, H160, U256};
use std::{sync::Arc, vec::Vec};

pub fn test_evm_call() {
	// given
	let (_, mut state, shard, mrenclave, ..) = test_setup();
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
		ita_sgx_runtime::HashedAddressMapping::into_account_id(sender_evm_acc);
	endow(&mut state, vec![(sender_evm_substrate_addr, 51_777_000_000_000)]);

	// Create the receiver account.
	let destination_evm_acc = H160::from_str("1000000000000000000000000000000000000001").unwrap();
	let destination_evm_substrate_addr =
		ita_sgx_runtime::HashedAddressMapping::into_account_id(destination_evm_acc);
	assert_eq!(
		state.execute_with(|| System::account(&destination_evm_substrate_addr).data.free),
		0
	);

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
	let repo = Arc::new(NodeMetadataRepository::<NodeMetadataMock>::default());
	TestStf::execute_call(&mut state, trusted_call, &mut opaque_vec, repo).unwrap();

	// then
	assert_eq!(
		transfer_value,
		state.execute_with(|| System::account(&destination_evm_substrate_addr).data.free)
	);
}

pub fn test_evm_counter() {
	// given
	let (_, mut state, shard, mrenclave, ..) = test_setup();
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
		ita_sgx_runtime::HashedAddressMapping::into_account_id(sender_evm_acc);
	endow(&mut state, vec![(sender_evm_substrate_addr, 51_777_000_000_000)]);

	// Smart Contract from Counter.sol.
	let smart_contract = "608060405234801561001057600080fd5b50600160008190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610377806100696000396000f3fe6080604052600436106100435760003560e01c80631003e2d21461004d57806333cf508014610076578063371303c0146100a157806358992216146100b857610044565b5b60056000819055005b34801561005957600080fd5b50610074600480360381019061006f9190610209565b6100e3565b005b34801561008257600080fd5b5061008b61013f565b6040516100989190610245565b60405180910390f35b3480156100ad57600080fd5b506100b6610148565b005b3480156100c457600080fd5b506100cd6101a4565b6040516100da91906102a1565b60405180910390f35b806000808282546100f491906102eb565b9250508190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b60008054905090565b600160008082825461015a91906102eb565b9250508190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550565b6000600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b600080fd5b6000819050919050565b6101e6816101d3565b81146101f157600080fd5b50565b600081359050610203816101dd565b92915050565b60006020828403121561021f5761021e6101ce565b5b600061022d848285016101f4565b91505092915050565b61023f816101d3565b82525050565b600060208201905061025a6000830184610236565b92915050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061028b82610260565b9050919050565b61029b81610280565b82525050565b60006020820190506102b66000830184610292565b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b60006102f6826101d3565b9150610301836101d3565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03821115610336576103356102bc565b5b82820190509291505056fea2646970667358221220b37e993e133ed19c840809cc8acbbba8116dee3744ba01c81044d75146805c9364736f6c634300080f0033";

	let trusted_call = TrustedCall::evm_create(
		sender_acc.clone(),
		sender_evm_acc,
		array_bytes::hex2bytes(smart_contract).unwrap().to_vec(),
		U256::from(0),
		10_000_000,    // gas limit
		U256::from(1), // max_fee_per_gas !>= min_gas_price defined in runtime
		None,
		Some(U256::from(0)),
		Vec::new(),
	)
	.sign(&sender.clone().into(), 0, &mrenclave, &shard);

	// when
	let execution_address = evm_create_address(sender_evm_acc, 0);
	let repo = Arc::new(NodeMetadataRepository::<NodeMetadataMock>::default());
	TestStf::execute_call(&mut state, trusted_call, &mut opaque_vec, repo).unwrap();

	// then
	assert_eq!(
		execution_address,
		H160::from_slice(
			&array_bytes::hex2bytes("0xce2c9e7f9c10049996173b2ca2d9a6815a70e890").unwrap(),
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
	// in solidity compile information you get the hash of the call
	let inc_function_input = array_bytes::hex2bytes("371303c0").unwrap();

	execute_and_verify_evm_call(
		sender_acc.clone(),
		sender_evm_acc,
		execution_address,
		inc_function_input.to_vec(),
		1,
		1,
		sender.clone().into(),
		&mrenclave,
		&shard,
		&mut state,
		&mut opaque_vec,
		2,
	);

	// Call the fallback function
	execute_and_verify_evm_call(
		sender_acc.clone(),
		sender_evm_acc,
		execution_address,
		Vec::new(), // Empty input calls the fallback function.
		2,
		2,
		sender.clone().into(),
		&mrenclave,
		&shard,
		&mut state,
		&mut opaque_vec,
		5,
	);

	// Call to inc() function
	// in solidity compile information you get the hash of the call
	execute_and_verify_evm_call(
		sender_acc.clone(),
		sender_evm_acc,
		execution_address,
		inc_function_input,
		3,
		3,
		sender.clone().into(),
		&mrenclave,
		&shard,
		&mut state,
		&mut opaque_vec,
		6,
	);

	// Call to add() function
	// in solidity compile information you get the hash of the call
	let function_hash = "1003e2d2";
	// 32 byte string of the value to add in hex
	let add_value = "0000000000000000000000000000000000000000000000000000000000000002";
	let add_function_input =
		array_bytes::hex2bytes(&format!("{}{}", function_hash, add_value)).unwrap();

	execute_and_verify_evm_call(
		sender_acc.clone(),
		sender_evm_acc,
		execution_address,
		add_function_input,
		4,
		4,
		sender.clone().into(),
		&mrenclave,
		&shard,
		&mut state,
		&mut opaque_vec,
		8,
	);
}

fn execute_and_verify_evm_call(
	sender_acc: AccountId,
	sender_evm_acc: H160,
	execution_address: H160,
	function_input: Vec<u8>,
	evm_nonce: i8,
	nonce: Index,
	pair: KeyPair,
	mrenclave: &[u8; 32],
	shard: &ShardIdentifier,
	state: &mut State,
	calls: &mut Vec<OpaqueCall>,
	counter_expected: u64,
) {
	let inc_call = TrustedCall::evm_call(
		sender_acc,
		sender_evm_acc,
		execution_address,
		function_input,
		U256::from(0),
		10_000_000,    // gas limit
		U256::from(1), // max_fee_per_gas !>= min_gas_price defined in runtime
		None,
		Some(U256::from(evm_nonce)),
		Vec::new(),
	)
	.sign(&pair, nonce, &mrenclave, &shard);
	let repo = Arc::new(NodeMetadataRepository::<NodeMetadataMock>::default());
	TestStf::execute_call(state, inc_call, calls, repo).unwrap();

	let counter_value = state
		.execute_with(|| get_evm_account_storages(&execution_address, &H256::zero()))
		.unwrap();
	assert_eq!(counter_value, H256::from_low_u64_be(counter_expected));
}

pub fn test_evm_create() {
	// given
	let (_, mut state, shard, mrenclave, ..) = test_setup();
	let mut opaque_vec = Vec::new();

	// Create the sender account.
	let sender = funded_pair();
	let sender_acc: AccountId = sender.public().into();
	let mut sender_evm_acc_slice: [u8; 20] = [0; 20];
	sender_evm_acc_slice
		.copy_from_slice((<[u8; 32]>::from(sender_acc.clone())).get(0..20).unwrap());
	let sender_evm_acc: H160 = sender_evm_acc_slice.into();
	// Ensure the substrate version of the evm account has some money.
	let sender_evm_substrate_addr = HashedAddressMapping::into_account_id(sender_evm_acc);
	endow(&mut state, vec![(sender_evm_substrate_addr.clone(), 51_777_000_000_000)]);

	// Bytecode from Counter.sol
	let smart_contract = "608060405234801561001057600080fd5b50600160008190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610377806100696000396000f3fe6080604052600436106100435760003560e01c80631003e2d21461004d57806333cf508014610076578063371303c0146100a157806358992216146100b857610044565b5b60056000819055005b34801561005957600080fd5b50610074600480360381019061006f9190610209565b6100e3565b005b34801561008257600080fd5b5061008b61013f565b6040516100989190610245565b60405180910390f35b3480156100ad57600080fd5b506100b6610148565b005b3480156100c457600080fd5b506100cd6101a4565b6040516100da91906102a1565b60405180910390f35b806000808282546100f491906102eb565b9250508190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b60008054905090565b600160008082825461015a91906102eb565b9250508190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550565b6000600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b600080fd5b6000819050919050565b6101e6816101d3565b81146101f157600080fd5b50565b600081359050610203816101dd565b92915050565b60006020828403121561021f5761021e6101ce565b5b600061022d848285016101f4565b91505092915050565b61023f816101d3565b82525050565b600060208201905061025a6000830184610236565b92915050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061028b82610260565b9050919050565b61029b81610280565b82525050565b60006020820190506102b66000830184610292565b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b60006102f6826101d3565b9150610301836101d3565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03821115610336576103356102bc565b5b82820190509291505056fea2646970667358221220b37e993e133ed19c840809cc8acbbba8116dee3744ba01c81044d75146805c9364736f6c634300080f0033";
	let smart_contract = array_bytes::hex2bytes(smart_contract).unwrap();

	let trusted_call = TrustedCall::evm_create(
		sender_acc.clone(),
		sender_evm_acc,
		smart_contract,
		U256::from(0), // value
		10_000_000,    // gas limit
		U256::from(1), // max_fee_per_gas !>= min_gas_price defined in runtime
		None,
		Some(U256::from(0)),
		Vec::new(),
	)
	.sign(&sender.clone().into(), 0, &mrenclave, &shard);

	// Should be the first call of the evm account
	let nonce = state.execute_with(|| System::account_nonce(&sender_evm_substrate_addr));
	assert_eq!(nonce, 0);
	let execution_address = evm_create_address(sender_evm_acc, nonce);
	let repo = Arc::new(NodeMetadataRepository::<NodeMetadataMock>::default());
	TestStf::execute_call(&mut state, trusted_call, &mut opaque_vec, repo).unwrap();

	assert_eq!(
		execution_address,
		H160::from_slice(
			&array_bytes::hex2bytes("0xce2c9e7f9c10049996173b2ca2d9a6815a70e890").unwrap(),
		)
	);
	assert!(state.execute_with(|| get_evm_account_codes(&execution_address).is_some()));

	// Ensure the nonce of the evm account has been increased by one
	// Should be the first call of the evm account
	let nonce = state.execute_with(|| System::account_nonce(&sender_evm_substrate_addr));
	assert_eq!(nonce, 1);
}

pub fn test_evm_create2() {
	// given
	let (_, mut state, shard, mrenclave, ..) = test_setup();
	let mut opaque_vec = Vec::new();

	// Create the sender account.
	let sender = funded_pair();
	let sender_acc: AccountId = sender.public().into();
	let mut sender_evm_acc_slice: [u8; 20] = [0; 20];
	sender_evm_acc_slice
		.copy_from_slice((<[u8; 32]>::from(sender_acc.clone())).get(0..20).unwrap());
	let sender_evm_acc: H160 = sender_evm_acc_slice.into();
	// Ensure the substrate version of the evm account has some money.
	let sender_evm_substrate_addr = HashedAddressMapping::into_account_id(sender_evm_acc);
	endow(&mut state, vec![(sender_evm_substrate_addr, 51_777_000_000_000)]);

	let salt = H256::from_low_u64_be(20);
	// Bytecode from Counter.sol
	let smart_contract = "608060405234801561001057600080fd5b50600160008190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610377806100696000396000f3fe6080604052600436106100435760003560e01c80631003e2d21461004d57806333cf508014610076578063371303c0146100a157806358992216146100b857610044565b5b60056000819055005b34801561005957600080fd5b50610074600480360381019061006f9190610209565b6100e3565b005b34801561008257600080fd5b5061008b61013f565b6040516100989190610245565b60405180910390f35b3480156100ad57600080fd5b506100b6610148565b005b3480156100c457600080fd5b506100cd6101a4565b6040516100da91906102a1565b60405180910390f35b806000808282546100f491906102eb565b9250508190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b60008054905090565b600160008082825461015a91906102eb565b9250508190555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550565b6000600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b600080fd5b6000819050919050565b6101e6816101d3565b81146101f157600080fd5b50565b600081359050610203816101dd565b92915050565b60006020828403121561021f5761021e6101ce565b5b600061022d848285016101f4565b91505092915050565b61023f816101d3565b82525050565b600060208201905061025a6000830184610236565b92915050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061028b82610260565b9050919050565b61029b81610280565b82525050565b60006020820190506102b66000830184610292565b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b60006102f6826101d3565b9150610301836101d3565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03821115610336576103356102bc565b5b82820190509291505056fea2646970667358221220b37e993e133ed19c840809cc8acbbba8116dee3744ba01c81044d75146805c9364736f6c634300080f0033";
	let smart_contract = array_bytes::hex2bytes(smart_contract).unwrap();

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
	let execution_address = evm_create2_address(sender_evm_acc, salt, code_hash);
	let repo = Arc::new(NodeMetadataRepository::<NodeMetadataMock>::default());
	TestStf::execute_call(&mut state, trusted_call, &mut opaque_vec, repo).unwrap();

	// then
	assert_eq!(
		execution_address,
		H160::from_slice(
			&array_bytes::hex2bytes("0xe07ad7925f6b2b10c5a7653fb16db7a984059d11").unwrap(),
		)
	);

	assert!(state.execute_with(|| get_evm_account_codes(&execution_address).is_some()));
}
