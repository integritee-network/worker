use crate::{error::Error, StorageProofChecker};
use frame_support::ensure;
use itp_types::storage::{StorageEntry, StorageEntryVerified};
use sp_runtime::traits::Header as HeaderT;
use sp_std::prelude::Vec;

pub trait VerifyStorageProof {
	fn verify_storage_proof<Header: HeaderT>(
		self,
		header: &Header,
	) -> Result<StorageEntryVerified<Vec<u8>>, Error>;
}

impl VerifyStorageProof for StorageEntry<Vec<u8>> {
	fn verify_storage_proof<Header: HeaderT>(
		self,
		header: &Header,
	) -> Result<StorageEntryVerified<Vec<u8>>, Error> {
		let proof = self.proof.as_ref().ok_or(Error::NoProofSupplied)?;
		let actual = StorageProofChecker::<<Header as HeaderT>::Hashing>::check_proof(
			*header.state_root(),
			&self.key,
			proof.to_vec(),
		)?;

		// Todo: Why do they do it like that, we could supply the proof only and get the value from the proof directly??
		ensure!(actual == self.value, Error::WrongValue);

		Ok(StorageEntryVerified { key: self.key, value: self.value })
	}
}

/// Verify a set of storage entries
pub fn verify_storage_entries<S, Header>(
	entries: impl IntoIterator<Item = S>,
	header: &Header,
) -> Result<Vec<StorageEntryVerified<Vec<u8>>>, Error>
where
	S: Into<StorageEntry<Vec<u8>>>,
	Header: HeaderT,
{
	let iter = into_storage_entry_iter(entries);
	let mut verified_entries = Vec::with_capacity(iter.size_hint().0);

	for e in iter {
		verified_entries.push(e.verify_storage_proof(header)?);
	}
	Ok(verified_entries)
}

pub fn into_storage_entry_iter<'a, S>(
	source: impl IntoIterator<Item = S> + 'a,
) -> impl Iterator<Item = StorageEntry<Vec<u8>>> + 'a
where
	S: Into<StorageEntry<Vec<u8>>>,
{
	source.into_iter().map(|s| s.into())
}
