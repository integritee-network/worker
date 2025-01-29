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
	evm::commands::evm_command_utils::get_trusted_evm_nonce,
	get_basic_signing_info_from_args,
	trusted_cli::TrustedCli,
	trusted_command_utils::get_trusted_account_info,
	trusted_operation::{perform_trusted_operation, send_direct_request},
	Cli, CliResult, CliResultOk,
};
use ita_stf::TrustedCall;
use itp_stf_primitives::{traits::TrustedCallSigning, types::KeyPair};
use log::*;
use sp_core::{crypto::Ss58Codec, H160, U256};
use std::{boxed::Box, vec::Vec};

#[derive(Parser)]
pub struct EvmCallCommands {
	/// Sender's incognito AccountId in ss58check format, mnemonic or hex seed
	from: String,

	/// Execution address of the smart contract
	execution_address: String,

	/// Function hash
	function: String,

	/// session proxy who can sign on behalf of the account
	#[clap(long)]
	session_proxy: Option<String>,
}

impl EvmCallCommands {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let (sender, signer, mrenclave, shard) =
			get_basic_signing_info_from_args!(self.from, self.session_proxy, cli, trusted_args);

		info!("senders ss58 is {}", sender.to_ss58check());

		let mut sender_evm_acc_slice: [u8; 20] = [0; 20];
		sender_evm_acc_slice
			.copy_from_slice((<[u8; 32]>::from(sender.clone())).get(0..20).unwrap());
		let sender_evm_acc: H160 = sender_evm_acc_slice.into();

		info!("senders evm account is {}", sender_evm_acc);

		let execution_address =
			H160::from_slice(&array_bytes::hex2bytes(&self.execution_address).unwrap());

		let function_hash = array_bytes::hex2bytes(&self.function).unwrap();

		let nonce = get_trusted_account_info(cli, trusted_args, &sender, &signer)
			.map(|info| info.nonce)
			.unwrap_or_default();

		let evm_nonce = get_trusted_evm_nonce(cli, trusted_args, &sender, &signer);

		println!("calling smart contract function");
		let function_call = TrustedCall::evm_call(
			sender,
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
		.sign(&KeyPair::Sr25519(Box::new(signer)), nonce, &mrenclave, &shard)
		.into_trusted_operation(trusted_args.direct);

		if trusted_args.direct {
			Ok(send_direct_request(cli, trusted_args, &function_call).map(|_| CliResultOk::None)?)
		} else {
			Ok(perform_trusted_operation::<()>(cli, trusted_args, &function_call)
				.map(|_| CliResultOk::None)?)
		}
	}
}
