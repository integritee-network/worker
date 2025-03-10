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
	trusted_cli::TrustedCli, trusted_command_utils::get_pair_from_str,
	trusted_operation::perform_trusted_operation, Cli, CliError, CliResult, CliResultOk,
};
use ita_stf::{Getter, TrustedCallSigned, TrustedGetter};
use itp_stf_primitives::types::{KeyPair, TrustedOperation};
use itp_types::AccountId;
use log::*;
use sp_core::{crypto::Ss58Codec, Pair, H160, H256};

#[derive(Parser)]
pub struct EvmReadCommands {
	/// Sender's incognito AccountId in ss58check format, mnemonic or hex seed
	from: String,

	/// Execution address of the smart contract
	execution_address: String,
}

impl EvmReadCommands {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let sender = get_pair_from_str(cli, trusted_args, &self.from);
		let sender_acc: AccountId = sender.public().into();

		info!("senders ss58 is {}", sender.public().to_ss58check());

		let mut sender_evm_acc_slice: [u8; 20] = [0; 20];
		sender_evm_acc_slice
			.copy_from_slice((<[u8; 32]>::from(sender_acc.clone())).get(0..20).unwrap());
		let sender_evm_acc: H160 = sender_evm_acc_slice.into();

		info!("senders evm account is {}", sender_evm_acc);

		let execution_address =
			H160::from_slice(&array_bytes::hex2bytes(&self.execution_address).unwrap());

		let top = TrustedOperation::<TrustedCallSigned, Getter>::get(Getter::trusted(
			TrustedGetter::evm_account_storages(sender_acc, execution_address, H256::zero())
				.sign(&KeyPair::Sr25519(Box::new(sender))),
		));
		match perform_trusted_operation::<H256>(cli, trusted_args, &top) {
			Ok(hash) => {
				println!("{:?}", hash);
				Ok(CliResultOk::H256 { hash })
			},
			Err(e) => {
				error!("Nothing in state! Reason: {:?} !", e);
				Err(CliError::EvmRead { msg: "Nothing in state!".to_string() })
			},
		}
	}
}
