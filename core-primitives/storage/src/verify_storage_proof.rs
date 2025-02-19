use crate::{error::Error, StorageProofChecker};
use codec::{Decode, Encode};
use frame_support::ensure;
use itp_types::storage::{StorageEntry, StorageEntryVerified};
use sp_runtime::traits::Header as HeaderT;
use sp_std::prelude::Vec;

pub trait VerifyStorageProof<H: HeaderT, V: Encode + Decode + Clone> {
	fn verify_storage_proof(self, header: &H) -> Result<StorageEntryVerified<V>, Error>;
}

impl<H, V> VerifyStorageProof<H, V> for StorageEntry<V>
where
	V: Encode + Decode + Clone,
	H: HeaderT,
{
	fn verify_storage_proof(self, header: &H) -> Result<StorageEntryVerified<V>, Error> {
		let proof = self.proof.as_ref().ok_or(Error::NoProofSupplied)?;
		let actual = StorageProofChecker::<<H as HeaderT>::Hashing>::check_proof(
			*header.state_root(),
			&self.key,
			proof.to_vec(),
		)?;

		// Todo: Why do they do it like that, we could supply the proof only and get the value from the proof directly??
		ensure!(actual == self.value.clone().map(|v| v.encode()), Error::WrongValue);

		Ok(StorageEntryVerified { key: self.key, value: self.value })
	}
}

/// Verify a set of storage entries
pub fn verify_storage_entries<S, Header, V>(
	entries: impl IntoIterator<Item = S>,
	header: &Header,
) -> Result<Vec<StorageEntryVerified<V>>, Error>
where
	S: Into<StorageEntry<V>>,
	Header: HeaderT,
	V: Encode + Decode + Clone,
{
	let iter = into_storage_entry_iter(entries);
	let mut verified_entries = Vec::with_capacity(iter.size_hint().0);

	for e in iter {
		verified_entries.push(e.verify_storage_proof(header)?);
	}
	Ok(verified_entries)
}

pub fn into_storage_entry_iter<'a, S, V>(
	source: impl IntoIterator<Item = S> + 'a,
) -> impl Iterator<Item = StorageEntry<V>> + 'a
where
	S: Into<StorageEntry<V>>,
	V: Decode,
{
	source.into_iter().map(|s| s.into())
}
