#![cfg_attr(all(not(target_env = "sgx"), not(feature = "std")), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

use codec::{Decode, Encode};
#[cfg(feature = "sgx")]
use sgx_tstd as std;
pub use sp_core::crypto::AccountId32 as AccountId;
use sp_core::H256;
use sp_runtime::{
	generic::{Block as BlockG, Header as HeaderG, SignedBlock as SignedBlockG},
	traits::BlakeTwo256,
	OpaqueExtrinsic,
};
use std::vec::Vec;

use itp_storage::storage_entry::StorageEntry;
pub use its_primitives::{
	traits,
	types::{
		block,
		block::{
			BlockHash, BlockNumber as SidechainBlockNumber,
			ShardIdentifier as SidechainShardIdentifier,
		},
	},
};
pub use rpc::*;
pub mod rpc;

/// Substrate runtimes provide no string type. Hence, for arbitrary data of varying length the
/// `Vec<u8>` is used. In the polkadot-js the typedef `Text` is used to automatically
/// utf8 decode bytes into a string.
#[cfg(not(feature = "std"))]
pub type PalletString = Vec<u8>;

#[cfg(feature = "std")]
pub type PalletString = String;

pub type ShardIdentifier = H256;
pub type BlockNumber = u32;
pub type Header = HeaderG<BlockNumber, BlakeTwo256>;
pub type Block = BlockG<Header, OpaqueExtrinsic>;
pub type SignedBlock = SignedBlockG<Block>;

// Note in the pallet teerex this is a struct. But for the codec this does not matter.
#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, Debug)]
pub struct Request {
	pub shard: ShardIdentifier,
	pub cyphertext: Vec<u8>,
}

pub type IpfsHash = [u8; 46];

pub type ConfirmCallFn = ([u8; 2], ShardIdentifier, H256, Vec<u8>);
pub type ShieldFundsFn = ([u8; 2], Vec<u8>, u128, ShardIdentifier);
pub type CallWorkerFn = ([u8; 2], Request);

// Todo: move this improved enclave definition into a primitives crate in the pallet_teerex repo.
#[derive(Encode, Decode, Default, Clone, PartialEq, sp_core::RuntimeDebug)]
pub struct EnclaveGen<AccountId> {
	pub pubkey: AccountId,
	// FIXME: this is redundant information
	pub mr_enclave: [u8; 32],
	pub timestamp: u64,
	// unix epoch in milliseconds
	pub url: PalletString, // utf8 encoded url
}

impl<AccountId> EnclaveGen<AccountId> {
	pub fn new(pubkey: AccountId, mr_enclave: [u8; 32], timestamp: u64, url: PalletString) -> Self {
		Self { pubkey, mr_enclave, timestamp, url }
	}
}

pub type Enclave = EnclaveGen<AccountId>;

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub enum DirectRequestStatus {
	/// Direct request was successfully executed
	Ok,
	/// Trusted Call Status
	TrustedOperationStatus(TrustedOperationStatus),
	/// Direct request could not be executed
	Error,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub enum TrustedOperationStatus {
	/// TrustedOperation is submitted to the top pool.
	Submitted,
	/// TrustedOperation is part of the future queue.
	Future,
	/// TrustedOperation is part of the ready queue.
	Ready,
	/// The operation has been broadcast to the given peers.
	Broadcast,
	/// TrustedOperation has been included in block with given hash.
	InSidechainBlock(BlockHash),
	/// The block this operation was included in has been retracted.
	Retracted,
	/// Maximum number of finality watchers has been reached,
	/// old watchers are being removed.
	FinalityTimeout,
	/// TrustedOperation has been finalized by a finality-gadget, e.g GRANDPA
	Finalized,
	/// TrustedOperation has been replaced in the pool, by another operation
	/// that provides the same tags. (e.g. same (sender, nonce)).
	Usurped,
	/// TrustedOperation has been dropped from the pool because of the limit.
	Dropped,
	/// TrustedOperation is no longer valid in the current state.
	Invalid,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub enum WorkerRequest {
	ChainStorage(Vec<u8>, Option<BlockHash>), // (storage_key, at_block)
}

#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub enum WorkerResponse<V: Encode + Decode> {
	ChainStorage(Vec<u8>, Option<V>, Option<Vec<Vec<u8>>>), // (storage_key, storage_value, storage_proof)
}

impl From<WorkerResponse<Vec<u8>>> for StorageEntry<Vec<u8>> {
	fn from(response: WorkerResponse<Vec<u8>>) -> Self {
		match response {
			WorkerResponse::ChainStorage(key, value, proof) => StorageEntry { key, value, proof },
		}
	}
}
