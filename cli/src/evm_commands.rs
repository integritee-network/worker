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

use crate::{
	get_layer_two_nonce,
	trusted_command_utils::{get_identifiers, get_pair_from_str},
	trusted_commands::TrustedArgs,
	trusted_operation::perform_trusted_operation,
	Cli,
};
use codec::Decode;
use ita_stf::{
	evm_helpers::evm_create_address, Index, KeyPair, TrustedCall, TrustedGetter, TrustedOperation,
};
use itp_types::AccountId;
use log::*;
use pallet_evm::{AddressMapping, HashedAddressMapping};
use sp_core::{crypto::Ss58Codec, Pair, H160, H256, U256};
use sp_runtime::traits::BlakeTwo256;
use std::{string::ToString, vec::Vec};
use substrate_api_client::utils::FromHexString;

macro_rules! get_layer_two_evm_nonce {
	($signer_pair:ident, $cli:ident, $trusted_args:ident ) => {{
		let top: TrustedOperation = TrustedGetter::evm_nonce($signer_pair.public().into())
			.sign(&KeyPair::Sr25519($signer_pair.clone()))
			.into();
		let res = perform_trusted_operation($cli, $trusted_args, &top);
		let nonce: Index = if let Some(n) = res {
			if let Ok(nonce) = Index::decode(&mut n.as_slice()) {
				nonce
			} else {
				0
			}
		} else {
			0
		};
		debug!("got layer two nonce: {:?}", nonce);
		nonce
	}};
}

#[derive(Subcommand)]
pub enum EvmCommands {
	/// Create smart contract
	EvmCreate {
		/// Sender's incognito AccountId in ss58check format
		from: String,

		/// Smart Contract in Hex format
		smart_contract: String,
	},

	/// Read smart contract storage
	EvmRead {
		/// Sender's incognito AccountId in ss58check format
		from: String,

		/// Execution address of the smart contract
		execution_address: String,
	},

	/// Create smart contract
	EvmCall {
		/// Sender's incognito AccountId in ss58check format
		from: String,

		/// Execution address of the smart contract
		execution_address: String,

		/// Function hash
		function: String,
	},
}

pub fn match_evm_commands(cli: &Cli, trusted_args: &TrustedArgs, evm_command: &EvmCommands) {
	match &evm_command {
		EvmCommands::EvmCreate { from, smart_contract } =>
			evm_create(cli, trusted_args, from, smart_contract),
		EvmCommands::EvmRead { from, execution_address } =>
			evm_read_storage(cli, trusted_args, from, execution_address),
		EvmCommands::EvmCall { from, execution_address, function } =>
			evm_call(cli, trusted_args, from, execution_address, function),
	}
}

fn evm_create(cli: &Cli, trusted_args: &TrustedArgs, arg_from: &str, smart_contract: &str) {
	let from = get_pair_from_str(trusted_args, arg_from);
	let from_acc: AccountId = from.public().into();
	println!("from ss58 is {}", from.public().to_ss58check());

	let mut sender_evm_acc_slice: [u8; 20] = [0; 20];
	sender_evm_acc_slice.copy_from_slice((<[u8; 32]>::from(from_acc.clone())).get(0..20).unwrap());
	let sender_evm_acc: H160 = sender_evm_acc_slice.into();

	let (mrenclave, shard) = get_identifiers(trusted_args);

	let sender_evm_substrate_addr =
		HashedAddressMapping::<BlakeTwo256>::into_account_id(sender_evm_acc);
	println!("Trying to get nonce of evm account {:?}", sender_evm_substrate_addr.to_ss58check());

	let nonce = get_layer_two_nonce!(from, cli, trusted_args);
	let evm_account_nonce = get_layer_two_evm_nonce!(from, cli, trusted_args);

	let top = TrustedCall::evm_create(
		from_acc,
		sender_evm_acc,
		Vec::from_hex(smart_contract.to_string()).unwrap(),
		U256::from(0),
		967295,        // gas limit
		U256::from(1), // max_fee_per_gas !>= min_gas_price defined in runtime
		None,
		None,
		Vec::new(),
	)
	.sign(&from.into(), nonce, &mrenclave, &shard)
	.into_trusted_operation(trusted_args.direct);

	let _ = perform_trusted_operation(cli, trusted_args, &top);

	let execution_address = evm_create_address(sender_evm_acc, evm_account_nonce);
	info!("trusted call evm_create executed");
	println!("Created the smart contract with address {:?}", execution_address);
}

fn evm_read_storage(
	cli: &Cli,
	trusted_args: &TrustedArgs,
	arg_from: &str,
	execution_address_str: &str,
) {
	let sender = get_pair_from_str(trusted_args, arg_from);
	let sender_acc: AccountId = sender.public().into();

	println!("senders ss58 is {}", sender.public().to_ss58check());

	let mut sender_evm_acc_slice: [u8; 20] = [0; 20];
	sender_evm_acc_slice
		.copy_from_slice((<[u8; 32]>::from(sender_acc.clone())).get(0..20).unwrap());
	let sender_evm_acc: H160 = sender_evm_acc_slice.into();

	println!("senders evm account is {}", sender_evm_acc);

	let execution_address =
		H160::from_slice(&Vec::from_hex(execution_address_str.to_string()).unwrap());

	let top: TrustedOperation =
		TrustedGetter::evm_account_storages(sender_acc, execution_address, H256::zero())
			.sign(&KeyPair::Sr25519(sender))
			.into();
	let res = perform_trusted_operation(cli, trusted_args, &top);

	debug!("received result for balance");
	let val = if let Some(v) = res {
		if let Ok(vd) = H256::decode(&mut v.as_slice()) {
			vd
		} else {
			error!("could not decode value. {:x?}", v);
			H256::zero()
		}
	} else {
		error!("Nothing in state!");
		H256::zero()
	};

	println!("{:?}", val);
}

fn evm_call(
	cli: &Cli,
	trusted_args: &TrustedArgs,
	arg_from: &str,
	execution_address_str: &str,
	function: &str,
) {
	let sender = get_pair_from_str(trusted_args, arg_from);
	let sender_acc: AccountId = sender.public().into();

	println!("senders ss58 is {}", sender.public().to_ss58check());

	let mut sender_evm_acc_slice: [u8; 20] = [0; 20];
	sender_evm_acc_slice
		.copy_from_slice((<[u8; 32]>::from(sender_acc.clone())).get(0..20).unwrap());
	let sender_evm_acc: H160 = sender_evm_acc_slice.into();

	println!("senders evm account is {}", sender_evm_acc);

	let execution_address =
		H160::from_slice(&Vec::from_hex(execution_address_str.to_string()).unwrap());

	let function_hash = Vec::from_hex(function.to_string()).unwrap();

	let (mrenclave, shard) = get_identifiers(trusted_args);
	let nonce = get_layer_two_nonce!(sender, cli, trusted_args);
	let evm_nonce = get_layer_two_evm_nonce!(sender, cli, trusted_args);

	println!("calling smart contract function");
	let function_call = TrustedCall::evm_call(
		sender_acc,
		sender_evm_acc,
		execution_address,
		function_hash,
		U256::from(0),
		10_000_000,    // gas limit
		U256::from(1), // max_fee_per_gas !>= min_gas_price defined in runtime
		None,
		Some(U256::from(evm_nonce)),
		Vec::new(),
	)
	.sign(&KeyPair::Sr25519(sender), nonce, &mrenclave, &shard)
	.into_trusted_operation(trusted_args.direct);
	let _ = perform_trusted_operation(cli, trusted_args, &function_call);
}
