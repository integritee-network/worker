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
	command_utils::format_moment, trusted_cli::TrustedCli,
	trusted_command_utils::get_pair_from_str, trusted_operation::perform_trusted_operation, Cli,
	CliResult, CliResultOk,
};

use codec::Decode;
use ita_stf::{
	guess_the_number::GuessTheNumberTrustedCall, Getter, TrustedCall, TrustedCallSigned,
	TrustedGetter,
};
use itp_stf_primitives::types::{KeyPair, TrustedOperation};
use itp_types::Moment;
use log::error;
use pallet_notes::{BucketIndex, TimestampedTrustedNote, TrustedNote};
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
		let notes = perform_trusted_operation::<Vec<TimestampedTrustedNote<Moment>>>(
			cli,
			trusted_args,
			&top,
		)
		.unwrap();
		for tnote in notes.clone() {
			let datetime_str = format_moment(tnote.timestamp);
			match tnote.note {
				TrustedNote::SuccessfulTrustedCall(encoded_call) => {
					if let Ok(call) = TrustedCall::decode(&mut encoded_call.as_slice()) {
						match call {
							TrustedCall::balance_transfer_with_note(from, to, amount, msg) => {
								println!(
									"[{}] TrustedCall::balance_transfer_with_note from: {:?}, to: {:?}, amount: {}  msg: {}",
									datetime_str,
									from,
									to,
									amount,
									String::from_utf8_lossy(msg.as_ref())
								);
							},
							TrustedCall::balance_transfer(from, to, amount) => {
								println!(
									"[{}] TrustedCall::balance_transfer from: {:?}, to: {:?}, amount: {}",
									datetime_str,
									from,
									to,
									amount
								);
							},
							TrustedCall::balance_unshield(from, to, amount, shard) => {
								println!(
									"[{}] TrustedCall::balance_unshield from: {:?}, to: {:?}, amount: {}, shard: {}",
									datetime_str,
									from,
									to,
									amount,
									shard
								);
							},
							TrustedCall::balance_shield(_, to, amount, parentchain_id) => {
								println!(
									"[{}] TrustedCall::balance_shield from: {:?}, to: {:?}, amount: {}",
									datetime_str,
									parentchain_id, to, amount
								);
							},
							TrustedCall::guess_the_number(GuessTheNumberTrustedCall::guess(
								sender,
								guess,
							)) => {
								println!(
									"[{}] TrustedCall::guess_the_number::guess sender: {:?}, guess: {}",
									datetime_str,
									sender, guess,
								);
							},
							_ => println!("[{}] {:?}", datetime_str, call),
						}
					} else {
						error!("failed to decode note. check version")
					}
				},
				_ => println!("{:?}", tnote.note),
			}
		}
		Ok(CliResultOk::Notes { notes })
	}
}
