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
	get_layer_two_evm_nonce, get_layer_two_nonce,
	trusted_command_utils::{get_identifiers, get_pair_from_str},
	trusted_commands::TrustedArgs,
	trusted_operation::perform_trusted_operation,
	Cli,
};
use codec::Decode;
use ita_stf::{
	evm_helpers::evm_create_address, Index, TrustedCall, TrustedGetter, TrustedOperation,
};
use itp_stf_primitives::types::KeyPair;
use itp_types::AccountId;
use log::*;
use pallet_evm::{AddressMapping, HashedAddressMapping};
use sp_core::{crypto::Ss58Codec, Pair, H160, U256};
use sp_runtime::traits::BlakeTwo256;
use std::vec::Vec;
use substrate_api_client::utils::FromHexString;

#[derive(Parser)]
pub struct EvmCreateCommands {
	/// Sender's incognito AccountId in ss58check format
	from: String,

	/// Smart Contract in Hex format
	smart_contract: String,
}

impl EvmCreateCommands {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedArgs) {
		let from = get_pair_from_str(trusted_args, &self.from);
		let from_acc: AccountId = from.public().into();
		println!("from ss58 is {}", from.public().to_ss58check());

		let mut sender_evm_acc_slice: [u8; 20] = [0; 20];
		sender_evm_acc_slice
			.copy_from_slice((<[u8; 32]>::from(from_acc.clone())).get(0..20).unwrap());
		let sender_evm_acc: H160 = sender_evm_acc_slice.into();

		let (mrenclave, shard) = get_identifiers(trusted_args);

		let sender_evm_substrate_addr =
			HashedAddressMapping::<BlakeTwo256>::into_account_id(sender_evm_acc);
		println!(
			"Trying to get nonce of evm account {:?}",
			sender_evm_substrate_addr.to_ss58check()
		);

		let nonce = get_layer_two_nonce!(from, cli, trusted_args);
		let evm_account_nonce = get_layer_two_evm_nonce!(from, cli, trusted_args);

		let top = TrustedCall::evm_create(
			from_acc,
			sender_evm_acc,
			Vec::from_hex(self.smart_contract.to_string()).unwrap(),
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
}
