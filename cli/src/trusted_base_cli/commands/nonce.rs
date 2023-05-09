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
	get_layer_two_nonce, trusted_cli::TrustedCli, trusted_command_utils::get_pair_from_str,
	trusted_operation::perform_trusted_operation, Cli, CliResult, CliResultOk,
};
use codec::Decode;
use ita_stf::{Index, TrustedGetter, TrustedOperation};
use itp_stf_primitives::types::KeyPair;
use log::*;
use sp_core::Pair;

#[derive(Parser)]
pub struct NonceCommand {
	/// AccountId in ss58check format
	account: String,
}

impl NonceCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let who = get_pair_from_str(trusted_args, &self.account);
		println!("{}", get_layer_two_nonce!(who, cli, trusted_args));
		Ok(CliResultOk::None)
	}
}
