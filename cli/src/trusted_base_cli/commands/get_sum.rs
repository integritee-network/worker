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
	trusted_operation::perform_trusted_operation, Cli,
};
use codec::Decode;
use ita_stf::{TrustedGetter, TrustedOperation};
use itp_stf_primitives::types::KeyPair;
use log::{debug, info, warn};
use sp_core::Pair;

#[derive(Parser)]
pub struct GetSumCommand {
	/// AccountId in ss58check format
	account: String,
}

impl GetSumCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) {
		println!("Result: {:?}", get_sum(cli, trusted_args, &self.account));
	}
}

pub(crate) fn get_sum(cli: &Cli, trusted_args: &TrustedCli, arg_who: &str) -> Option<u32> {
	debug!("arg_who = {:?}", arg_who);
	let who = get_pair_from_str(trusted_args, arg_who);
	let top: TrustedOperation = TrustedGetter::add_num(who.public().into())
		.sign(&KeyPair::Sr25519(Box::new(who)))
		.into();

	let res = perform_trusted_operation(cli, trusted_args, &top);
	match res {
		Some(value) => {
			let value = u32::decode(&mut value.as_slice()).unwrap();
			info!("Found sum: {:?}", value);

			Some(value)
		},
		None => {
			warn!("Sum not found");
			None
		},
	}
}
