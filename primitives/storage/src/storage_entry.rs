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

pub trait Verify {
	fn verify_proof<Header: HeaderT>(&self, header: &Header) -> Result<(), Error>;
}

impl Verify for StorageEntry<Vec<u8>> {
	fn verify_proof<Header: HeaderT>(&self, header: &Header) -> Result<(), Error> {
		let proof = self.proof.as_ref().ok_or(Error::NoProofSupplied)?;
		let actual = StorageProofChecker::<<Header as HeaderT>::Hashing>::check_proof(
			*header.state_root(),
			&self.key,
			proof.to_vec(),
		)?;

		// Todo: Why do they do it like that, we could supply the proof only and get the value from the proof directly??
		ensure!(&actual == &self.value, Error::WrongValue);
		Ok(())
	}
}

pub fn into_storage_entry_iter<'a, S>(
	source: impl IntoIterator<Item = S> + 'a,
) -> impl Iterator<Item = StorageEntry<Vec<u8>>> + 'a
where
	S: Into<StorageEntry<Vec<u8>>>,
{
	source.into_iter().map(|s| s.into())
}
