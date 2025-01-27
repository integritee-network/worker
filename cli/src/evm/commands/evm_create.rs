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
	get_sender_and_signer_from_args,
	trusted_cli::TrustedCli,
	trusted_command_utils::{get_identifiers, get_pair_from_str, get_trusted_account_info},
	trusted_operation::{perform_trusted_operation, send_direct_request},
	Cli, CliResult, CliResultOk,
};
use ita_stf::{evm_helpers::evm_create_address, TrustedCall};
use itp_stf_primitives::traits::TrustedCallSigning;
use log::*;
use pallet_evm::{AddressMapping, HashedAddressMapping};
use sp_core::{crypto::Ss58Codec, H160, U256};
use sp_runtime::traits::BlakeTwo256;
use std::vec::Vec;

#[derive(Parser)]
pub struct EvmCreateCommands {
	/// Sender's incognito AccountId in ss58check format, mnemonic or hex seed
	from: String,

	/// Smart Contract in Hex format
	smart_contract: String,

	/// session proxy who can sign on behalf of the account
	#[clap(long)]
	session_proxy: Option<String>,
}

impl EvmCreateCommands {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let (sender, signer) =
			get_sender_and_signer_from_args!(self.from, self.session_proxy, trusted_args);
		println!("from ss58 is {}", sender.to_ss58check());

		let mut sender_evm_acc_slice: [u8; 20] = [0; 20];
		sender_evm_acc_slice
			.copy_from_slice((<[u8; 32]>::from(sender.clone())).get(0..20).unwrap());
		let sender_evm_acc: H160 = sender_evm_acc_slice.into();

		let (mrenclave, shard) = get_identifiers(trusted_args);

		let sender_evm_substrate_addr =
			HashedAddressMapping::<BlakeTwo256>::into_account_id(sender_evm_acc);

		println!(
			"Trying to get nonce of evm account {:?}",
			sender_evm_substrate_addr.to_ss58check()
		);

		let nonce = get_trusted_account_info(cli, trusted_args, &sender, &signer)
			.map(|info| info.nonce)
			.unwrap_or_default();

		let evm_nonce = get_trusted_evm_nonce(cli, trusted_args, &sender, &signer);

		let top = TrustedCall::evm_create(
			sender,
			sender_evm_acc,
			array_bytes::hex2bytes(&self.smart_contract).unwrap().to_vec(),
			U256::from(0),
			967295,        // gas limit
			U256::from(1), // max_fee_per_gas !>= min_gas_price defined in runtime
			None,
			None,
			Vec::new(),
		)
		.sign(&signer.into(), nonce, &mrenclave, &shard)
		.into_trusted_operation(trusted_args.direct);

		if trusted_args.direct {
			send_direct_request(cli, trusted_args, &top).map(|_| CliResultOk::None)?;
		} else {
			perform_trusted_operation::<()>(cli, trusted_args, &top).map(|_| CliResultOk::None)?;
		}

		let execution_address = evm_create_address(sender_evm_acc, evm_nonce);
		info!("trusted call evm_create executed");
		println!("Created the smart contract with address {:?}", execution_address);
		Ok(CliResultOk::H160 { hash: execution_address })
	}
}
