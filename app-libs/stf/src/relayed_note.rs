use codec::{Decode, Encode};
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
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub enum RelayedNoteRetreivalInfo {
	/// the message is included within and not actually relayed
	Here { msg: Vec<u8> },
	/// the message is stored on ipfs, encrypted with the provided key
	Ipfs { cid: IpfsCid, encryption_key: [u8; 32] },
	/// the message is relayed through an undeclared channel which is assumed to be
	/// known by the recipient, but the encryption key is provided
	Undeclared { encryption_key: [u8; 32] },
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
