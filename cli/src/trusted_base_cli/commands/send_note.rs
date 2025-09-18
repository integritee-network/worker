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
	get_basic_signing_info_from_args,
	trusted_cli::TrustedCli,
	trusted_command_utils::{get_accountid_from_str, get_trusted_account_info},
	trusted_operation::{perform_trusted_operation, send_direct_request},
	Cli, CliResult, CliResultOk,
};
use ita_stf::{
	relayed_note::{ConversationId, NoteRelayType, RelayedNoteRequest},
	Getter, TrustedCall, TrustedCallSigned,
};
use itp_stf_primitives::{
	traits::TrustedCallSigning,
	types::{KeyPair, TrustedOperation},
};
use log::*;
use std::boxed::Box;

#[derive(Parser)]
pub struct SendNoteCommand {
	/// sender's account. AccountId in ss58check format, mnemonic or hex seed.
	sender: String,
	/// recipient of note. AccountId in ss58check format.
	recipient: String,

	/// plain message body in UTF8 encoding
	message: String,

	/// session proxy who can sign on behalf of the account
	#[clap(long)]
	session_proxy: Option<String>,

	/// Instruct the worker enclave to encrypt and relay the message via IPFS instead of onchain
	#[clap(long)]
	ipfs_proxy: bool,

	/// specify conversation ID
	#[clap(long)]
	conversation_id: Option<ConversationId>,
}

impl SendNoteCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let (sender, signer, mrenclave, shard) =
			get_basic_signing_info_from_args!(self.sender, self.session_proxy, cli, trusted_args);

		let to = get_accountid_from_str(&self.recipient);
		println!("send trusted call send-note to {}: {}", to, self.message);

		let nonce = get_trusted_account_info(cli, trusted_args, &sender, &signer)
			.map(|info| info.nonce)
			.unwrap_or_default();
		let top: TrustedOperation<TrustedCallSigned, Getter> = if self.ipfs_proxy {
			let request = RelayedNoteRequest {
				allow_onchain_fallback: false,
				relay_type: NoteRelayType::Ipfs,
				msg: self.message.as_bytes().to_vec(),
				maybe_encryption_key: None,
			};
			let conversation_id = self.conversation_id.unwrap_or_default();
			TrustedCall::send_relayed_note(sender, to, conversation_id, request)
				.sign(&KeyPair::Sr25519(Box::new(signer)), nonce, &mrenclave, &shard)
				.into_trusted_operation(trusted_args.direct)
		} else if self.conversation_id.is_some() {
			let request = RelayedNoteRequest {
				allow_onchain_fallback: false,
				relay_type: NoteRelayType::Here,
				msg: self.message.as_bytes().to_vec(),
				maybe_encryption_key: None,
			};
			let conversation_id = self.conversation_id.unwrap_or_default();
			TrustedCall::send_relayed_note(sender, to, conversation_id, request)
				.sign(&KeyPair::Sr25519(Box::new(signer)), nonce, &mrenclave, &shard)
				.into_trusted_operation(trusted_args.direct)
		} else {
			TrustedCall::send_note(sender, to, self.message.as_bytes().to_vec())
				.sign(&KeyPair::Sr25519(Box::new(signer)), nonce, &mrenclave, &shard)
				.into_trusted_operation(trusted_args.direct)
		};

		if trusted_args.direct {
			Ok(send_direct_request(cli, trusted_args, &top).map(|_| CliResultOk::None)?)
		} else {
			Ok(perform_trusted_operation::<()>(cli, trusted_args, &top)
				.map(|_| CliResultOk::None)?)
		}
	}
}
