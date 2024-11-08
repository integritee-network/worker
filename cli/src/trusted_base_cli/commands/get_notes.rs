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
	trusted_cli::TrustedCli,
	trusted_command_utils::{get_balance, get_pair_from_str},
	trusted_operation::perform_trusted_operation,
	Cli, CliResult, CliResultOk,
};
use ita_stf::{Getter, TrustedCallSigned, TrustedGetter};
use itp_stf_primitives::types::{KeyPair, TrustedOperation};
use pallet_notes::{BucketIndex, TrustedNote};
use sp_core::Pair;

#[derive(Parser)]
pub struct GetNotesCommand {
	/// AccountId in ss58check format, mnemonic or hex seed
	account: String,
	///
	bucket_index: BucketIndex,
}

impl GetNotesCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let who = get_pair_from_str(trusted_args, self.account.as_str());
		let top = TrustedOperation::<TrustedCallSigned, Getter>::get(Getter::trusted(
			TrustedGetter::notes_for(who.public().into(), self.bucket_index)
				.sign(&KeyPair::Sr25519(Box::new(who))),
		));
		let notes = perform_trusted_operation::<Vec<TrustedNote>>(cli, trusted_args, &top).unwrap();
		Ok(CliResultOk::Notes { notes })
	}
}
