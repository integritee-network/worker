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
use ita_stf::{Index, TrustedCall, TrustedGetter, TrustedOperation};
use itp_stf_primitives::types::KeyPair;
use itp_types::AccountId;
use log::*;
use sp_core::{crypto::Ss58Codec, Pair, H160, U256};
use std::{boxed::Box, vec::Vec};
use substrate_api_client::utils::FromHexString;

#[derive(Parser)]
pub struct EvmCallCommands {
	/// Sender's incognito AccountId in ss58check format
	from: String,

	/// Execution address of the smart contract
	execution_address: String,

	/// Function hash
	function: String,
}

impl EvmCallCommands {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedArgs) {
		let sender = get_pair_from_str(trusted_args, &self.from);
		let sender_acc: AccountId = sender.public().into();

		info!("senders ss58 is {}", sender.public().to_ss58check());

		let mut sender_evm_acc_slice: [u8; 20] = [0; 20];
		sender_evm_acc_slice
			.copy_from_slice((<[u8; 32]>::from(sender_acc.clone())).get(0..20).unwrap());
		let sender_evm_acc: H160 = sender_evm_acc_slice.into();

		info!("senders evm account is {}", sender_evm_acc);

		let execution_address =
			H160::from_slice(&Vec::from_hex(self.execution_address.to_string()).unwrap());

		let function_hash = Vec::from_hex(self.function.to_string()).unwrap();

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
		.sign(&KeyPair::Sr25519(Box::new(sender)), nonce, &mrenclave, &shard)
		.into_trusted_operation(trusted_args.direct);
		let _ = perform_trusted_operation(cli, trusted_args, &function_call);
	}
}
