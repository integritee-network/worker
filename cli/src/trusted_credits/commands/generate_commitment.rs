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
	command_utils::hash_from_hex,
	get_basic_signing_info_from_args,
	trusted_cli::TrustedCli,
	trusted_command_utils::get_trusted_account_info,
	trusted_operation::{perform_trusted_operation, send_direct_request},
	Cli, CliError, CliResult, CliResultOk,
};
use ita_stf::{credits::CreditsTrustedCall, Getter, TrustedCall, TrustedCallSigned};
use itp_stf_primitives::{
	traits::TrustedCallSigning,
	types::{KeyPair, TrustedOperation},
};
use itp_types::Hash;
use log::*;
use rand::Rng;
use sp_core::blake2_256;
use std::boxed::Box;

#[derive(Parser)]
pub struct GenerateCommitmentCommand {}

impl GenerateCommitmentCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let mut rng = rand::thread_rng();
		let random_bytes: [u8; 32] = rng.gen();
		let commitment = blake2_256(&random_bytes);
		println!("generated random secret and its commitment hash:");
		println!("secret: 0x{}", hex::encode(random_bytes));
		println!("commitment: 0x{}", hex::encode(commitment));
		Ok(CliResultOk::None)
	}
}
