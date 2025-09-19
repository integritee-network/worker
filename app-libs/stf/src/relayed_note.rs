/*
	Copyright 2021 Integritee AG

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

use codec::{Decode, Encode};
use core::fmt::Debug;
use itp_utils::IpfsCid;
use sp_std::vec::Vec;
pub type ConversationId = u32;

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub enum NoteRelayType {
	/// the note will be stored in chain state entirely
	Here,
	/// the note is stored on ipfs, encrypted with a symmetric key
	Ipfs,
	/// the note is relayed through an undeclared channel which is assumed to be
	/// known by the recipient
	Undeclared,
}

/// Necessary information for recipient to retrieve and potentially decrypt a relayed note
#[derive(Encode, Decode, Clone, PartialEq, Eq)]
pub enum RelayedNoteRetreivalInfo {
	/// the message is included within and not actually relayed
	Here { msg: Vec<u8> },
	/// the message is stored on ipfs, encrypted with the provided key
	Ipfs { cid: IpfsCid, encryption_key: [u8; 32] },
	/// the message is relayed through an undeclared channel which is assumed to be
	/// known by the recipient, but the encryption key is provided
	Undeclared { encryption_key: [u8; 32] },
}

impl Debug for RelayedNoteRetreivalInfo {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			RelayedNoteRetreivalInfo::Here { msg } => write!(
				f,
				"Here {{ msg: {} }}",
				core::str::from_utf8(msg).unwrap_or("<invalid utf8>")
			),
			RelayedNoteRetreivalInfo::Ipfs { cid, encryption_key } => write!(
				f,
				"Ipfs {{ cid: {:?}, encryption_key: 0x{} }}",
				cid,
				hex::encode(encryption_key)
			),
			RelayedNoteRetreivalInfo::Undeclared { encryption_key } =>
				write!(f, "Undeclared {{ encryption_key: 0x{} }}", hex::encode(encryption_key)),
		}
	}
}

/// A user request to relay a note to a specific conversation.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct RelayedNoteRequest {
	pub allow_onchain_fallback: bool,
	pub relay_type: NoteRelayType,
	pub msg: Vec<u8>,
	/// in the case of `Undeclared` relaying, this can be used to securely share the encryption key with the recipient
	pub maybe_encryption_key: Option<[u8; 32]>,
}

impl Default for RelayedNoteRequest {
	fn default() -> Self {
		RelayedNoteRequest {
			allow_onchain_fallback: true,
			relay_type: NoteRelayType::Here,
			msg: Vec::new(),
			maybe_encryption_key: None,
		}
	}
}
