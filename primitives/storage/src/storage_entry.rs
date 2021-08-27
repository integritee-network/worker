use crate::{error::Error, StorageProofChecker};
use codec::{Decode, Encode};
use frame_support::ensure;
use sp_runtime::traits::Header as HeaderT;
use sp_std::prelude::Vec;

#[derive(Default, Clone, Encode, Decode)]
pub struct StorageEntry<V> {
	pub key: Vec<u8>,
	pub value: Option<V>,
	pub proof: Option<Vec<Vec<u8>>>,
}

/// Contains private fields. We don't expose a public constructor. Hence, the only way
/// to get a `StorageEntryVerified` is via the `VerifyStorageProof` trait.
#[derive(Default, Clone, Encode, Decode)]
pub struct StorageEntryVerified<V> {
	key: Vec<u8>,
	value: Option<V>,
}

#[cfg(feature = "test")]
impl<V> StorageEntryVerified<V> {
	pub fn new(key: Vec<u8>, value: Option<V>) -> Self {
		Self { key, value }
	}
}

impl<V> StorageEntryVerified<V> {
	pub fn key(&self) -> &[u8] {
		&self.key
	}

	pub fn value(&self) -> &Option<V> {
		&self.value
	}

	/// Without accessing the the field directly but with getters only, we cannot partially
	/// own the struct. So we can't do: `hashmap.insert(self.key(), self.value())` if the getters
	/// consumed the `self`, which is needed to return owned values. Hence, we supply this method,
	/// to consume `self` and be able to use the values individually.
	pub fn into_tuple(self) -> (Vec<u8>, Option<V>) {
		(self.key, self.value)
	}
}

pub trait VerifyStorageProof {
	fn verify_storage_proof<Header: HeaderT, V: Decode>(
		self,
		header: &Header,
	) -> Result<StorageEntryVerified<V>, Error>;
}

impl VerifyStorageProof for StorageEntry<Vec<u8>> {
	fn verify_storage_proof<Header: HeaderT, V: Decode>(
		self,
		header: &Header,
	) -> Result<StorageEntryVerified<V>, Error> {
		let proof = self.proof.as_ref().ok_or(Error::NoProofSupplied)?;
		let actual = StorageProofChecker::<<Header as HeaderT>::Hashing>::check_proof(
			*header.state_root(),
			&self.key,
			proof.to_vec(),
		)?;

		// Todo: Why do they do it like that, we could supply the proof only and get the value from the proof directly??
		ensure!(actual == self.value, Error::WrongValue);

		Ok(StorageEntryVerified {
			key: self.key,
			value: self
				.value
				.map(|v| Decode::decode(&mut v.as_slice()))
				.transpose()
				.map_err(Error::Codec)?,
		})
	}
}

/// Verify a set of storage entries
pub fn verify_storage_entries<S, Header, V>(
	entries: impl IntoIterator<Item = S>,
	header: &Header,
) -> Result<Vec<StorageEntryVerified<V>>, Error>
where
	S: Into<StorageEntry<Vec<u8>>>,
	Header: HeaderT,
	V: Decode,
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
