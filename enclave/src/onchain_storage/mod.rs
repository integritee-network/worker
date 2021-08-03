use crate::ocall::ocall_api::EnclaveOnChainOCallApi;
use codec::{Decode, Encode};
use derive_more::From;
use frame_support::ensure;
use log::error;
use sp_runtime::traits::Header as HeaderT;
use sp_std::prelude::Vec;
use substratee_storage::{Error as ProofError, StorageProofChecker};
use substratee_worker_primitives::{WorkerRequest, WorkerResponse};

#[derive(Debug, PartialEq, Eq, From)]
pub enum Error {
	NoProofSupplied,
	/// Supplied storage value does not match the value from the proof
	WrongValue,
	Proof(ProofError),
	Codec(codec::Error),
}

#[derive(Default, Clone)]
pub struct StorageEntry<V: Decode> {
	pub key: Vec<u8>,
	pub value: Option<V>,
}

pub trait OnchainStorage {
	fn verify_proof<Header: HeaderT>(&self, header: &Header) -> Result<(), Error>;
	fn try_into_storage_entry<V: Decode>(self) -> Result<StorageEntry<V>, Error>;
	fn key(&self) -> &[u8];
	fn value(&self) -> &Option<Vec<u8>>;
}

impl OnchainStorage for WorkerResponse<Vec<u8>> {
	/// returns key value pair of verified storage
	fn verify_proof<Header: HeaderT>(&self, header: &Header) -> Result<(), Error> {
		match self {
			WorkerResponse::ChainStorage(key, value, proof) => {
				let proof = proof.as_ref().ok_or(Error::NoProofSupplied)?;
				let actual = StorageProofChecker::<<Header as HeaderT>::Hashing>::check_proof(
					*header.state_root(),
					&key,
					proof.to_vec(),
				)?;

				// Todo: Why do they do it like that, we could supply the proof only and get the value from the proof directly??
				ensure!(&actual == value, Error::WrongValue);
				Ok(())
			},
		}
	}

	fn try_into_storage_entry<V: Decode>(self) -> Result<StorageEntry<V>, Error> {
		match self {
			WorkerResponse::ChainStorage(key, value, _proof) => {
				let v: Option<V> = match value {
					Some(v) => Decode::decode(&mut v.as_slice())?,
					None => None,
				};
				Ok(StorageEntry { key, value: v })
			},
		}
	}

	fn key(&self) -> &[u8] {
		match self {
			WorkerResponse::ChainStorage(key, _, _) => key,
		}
	}

	fn value(&self) -> &Option<Vec<u8>> {
		match self {
			WorkerResponse::ChainStorage(_, value, _) => value,
		}
	}
}
