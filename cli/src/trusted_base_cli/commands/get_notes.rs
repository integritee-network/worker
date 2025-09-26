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
	guess_the_number::GuessTheNumberTrustedCall, relayed_note::RelayedNoteRetrievalInfo, Getter,
	TrustedCall, TrustedCallSigned, TrustedGetter,
};
use itp_sgx_crypto::{aes::Aes, StateCrypto};
use itp_stf_primitives::types::{KeyPair, TrustedOperation};
use itp_types::{AccountId, Moment};
use log::{debug, error};
use pallet_notes::{BucketIndex, TimestampedTrustedNote, TrustedNote};
use reqwest::blocking::get;
use sp_core::{crypto::Ss58Codec, Pair};

#[derive(Parser)]
pub struct GetNotesCommand {
	/// AccountId in ss58check format, mnemonic or hex seed
	account: String,
	///
	bucket_index: BucketIndex,
}

impl GetNotesCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let who = get_pair_from_str(cli, trusted_args, self.account.as_str());
		let who_accountid: AccountId = who.public().into();
		let top = TrustedOperation::<TrustedCallSigned, Getter>::get(Getter::trusted(
			TrustedGetter::notes_for(who_accountid.clone(), self.bucket_index)
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
									"[{}] TrustedCall::trusted_guess_the_number::guess sender: {:?}, guess: {}",
									datetime_str,
									sender, guess,
								);
							},
							TrustedCall::send_note(from, to, note) =>
								if from == who_accountid {
									println!(
										"[{}] Message to: {}: {}",
										datetime_str,
										to.to_ss58check(),
										String::from_utf8_lossy(note.as_ref())
									);
								} else {
									println!(
										"[{}] Message from: {}: {}",
										datetime_str,
										from.to_ss58check(),
										String::from_utf8_lossy(note.as_ref())
									);
								},
							TrustedCall::send_relayed_note_stripped(
								from,
								to,
								conversation_id,
								retrieval,
							) => {
								let msg = match retrieval {
									RelayedNoteRetrievalInfo::Ipfs { cid, encryption_key } => {
										debug!("fetching ipfs data for cid: {:?}", cid);
										let ciphertext = fetch_ipfs_data(
											&cli.ipfs_gateway_url,
											&cid.to_string(),
										)
										.unwrap();
										let plaintext = decrypt(&ciphertext, &encryption_key);
										String::from_utf8_lossy(&plaintext).to_string()
									},
									RelayedNoteRetrievalInfo::Here { msg } =>
										String::from_utf8_lossy(msg.as_ref()).to_string(),
									RelayedNoteRetrievalInfo::Undeclared { .. } => {
										"[encryption key provided: *****, but message relay is undeclared]".into()
									},
								};

								if from == who_accountid {
									println!(
										"[{}] Message in conversation {} to: {}: {:?}",
										datetime_str,
										conversation_id,
										to.to_ss58check(),
										msg
									);
								} else {
									println!(
										"[{}] Message in conversation {} from: {}: {:?}",
										datetime_str,
										conversation_id,
										from.to_ss58check(),
										msg
									);
								}
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

fn fetch_ipfs_data(gateway_url: &str, ipfs_hash: &str) -> Result<Vec<u8>, reqwest::Error> {
	let url = format!("{}/ipfs/{}", gateway_url.trim_end_matches('/'), ipfs_hash);
	debug!("Fetching ipfs data from url: {}", url);
	let response = get(&url)?;
	let bytes = response.bytes()?.to_vec();
	Ok(bytes)
}

fn decrypt(data: &[u8], encryption_key: &[u8; 32]) -> Vec<u8> {
	let key: [u8; 16] = encryption_key[0..16].try_into().unwrap();
	let iv: [u8; 16] = encryption_key[16..32].try_into().unwrap();
	debug!("decrypting with \n key 0x{} \n iv 0x{}", hex::encode(key), hex::encode(iv));
	let aes = Aes::new(key, iv);
	let mut decrypted_data = data.to_vec();
	aes.decrypt(&mut decrypted_data).unwrap();
	decrypted_data
}
