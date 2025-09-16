use codec::{Decode, Encode};
use itp_types::IpfsHash;
use sp_std::vec::Vec;
pub type ConversationId = u32;

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct RelayedNote {
	pub conversation_id: ConversationId,
	pub retreival_info: RelayedNoteRetreivalInfo,
}

/// Necessary information for recipient to retrieve and potentially decrypt a relayed note
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub enum RelayedNoteRetreivalInfo {
	/// the message is included within and not actually relayed
	Here { msg: Vec<u8> },
	/// the message is stored on ipfs, encrypted with the provided key
	Ipfs { cid: IpfsHash, encryption_key: [u8; 32] },
	/// the message is relayed through an undeclared channel which is assumed to be
	/// known by the recipient, but the encryption key is provided
	Undeclared { encryption_key: [u8; 32] },
}

/// A user request to relay a note to a specific conversation.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct RelayedNoteRequest {
	pub conversation_id: ConversationId,
	pub msg: Vec<u8>,
}
