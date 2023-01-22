// Copyright 2020-2023 Litentry Technologies GmbH.
// This file is part of Litentry.
//
// Litentry is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Litentry is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Litentry.  If not, see <https://www.gnu.org/licenses/>.

use crate::{error::Error, hash_of, ExecutionStatus, IndirectCallsExecutor};
use codec::{Decode, Encode, Error as CodecError};
use itp_node_api::{
	api_client::ParentchainUncheckedExtrinsic,
	metadata::{provider::AccessNodeMetadata, Error as MetadataError, NodeMetadataTrait},
};
use itp_sgx_crypto::{key_repository::AccessKey, ShieldingCryptoDecrypt, ShieldingCryptoEncrypt};
use itp_stf_executor::traits::StfEnclaveSigning;
use itp_top_pool_author::traits::AuthorApi;
use itp_types::H256;

pub mod call_worker;
pub mod shield_funds;

pub(crate) trait Executor<
	ShieldingKeyRepository,
	StfEnclaveSigner,
	TopPoolAuthor,
	NodeMetadataProvider,
> where
	ShieldingKeyRepository: AccessKey,
	ShieldingKeyRepository::KeyType: ShieldingCryptoDecrypt<Error = itp_sgx_crypto::Error>
		+ ShieldingCryptoEncrypt<Error = itp_sgx_crypto::Error>,
	StfEnclaveSigner: StfEnclaveSigning,
	TopPoolAuthor: AuthorApi<H256, H256> + Send + Sync + 'static,
	NodeMetadataProvider: AccessNodeMetadata,
	NodeMetadataProvider::MetadataType: NodeMetadataTrait,
{
	type Call: Decode + Encode + Clone;

	fn call_index(&self, call: Self::Call) -> [u8; 2];

	fn call_index_from_metadata(
		&self,
		metadata_type: &NodeMetadataProvider::MetadataType,
	) -> Result<[u8; 2], MetadataError>;

	fn is_target_call(&self, call: Self::Call, node_metadata: &NodeMetadataProvider) -> bool {
		node_metadata
			.get_from_metadata(|m| match self.call_index_from_metadata(m) {
				Ok(call_index) => self.call_index(call) == call_index,
				Err(_e) => false,
			})
			.unwrap_or(false)
	}

	fn decode(
		&self,
		input: &mut &[u8],
	) -> Result<ParentchainUncheckedExtrinsic<Self::Call>, CodecError> {
		ParentchainUncheckedExtrinsic::<Self::Call>::decode(input)
	}

	/// extrinisc in this function should execute successfully on parentchain
	fn execute(
		&self,
		context: &IndirectCallsExecutor<
			ShieldingKeyRepository,
			StfEnclaveSigner,
			TopPoolAuthor,
			NodeMetadataProvider,
		>,
		extrinsic: ParentchainUncheckedExtrinsic<Self::Call>,
	) -> Result<(), Error>;
}

pub(crate) trait DecorateExecutor<
	ShieldingKeyRepository,
	StfEnclaveSigner,
	TopPoolAuthor,
	NodeMetadataProvider,
>
{
	fn decode_and_execute(
		&self,
		context: &IndirectCallsExecutor<
			ShieldingKeyRepository,
			StfEnclaveSigner,
			TopPoolAuthor,
			NodeMetadataProvider,
		>,
		input: &mut &[u8],
	) -> Result<ExecutionStatus<H256>, Error>;
}

impl<E, ShieldingKeyRepository, StfEnclaveSigner, TopPoolAuthor, NodeMetadataProvider>
	DecorateExecutor<ShieldingKeyRepository, StfEnclaveSigner, TopPoolAuthor, NodeMetadataProvider>
	for E
where
	E: Executor<ShieldingKeyRepository, StfEnclaveSigner, TopPoolAuthor, NodeMetadataProvider>,
	ShieldingKeyRepository: AccessKey,
	ShieldingKeyRepository::KeyType: ShieldingCryptoDecrypt<Error = itp_sgx_crypto::Error>
		+ ShieldingCryptoEncrypt<Error = itp_sgx_crypto::Error>,
	StfEnclaveSigner: StfEnclaveSigning,
	TopPoolAuthor: AuthorApi<H256, H256> + Send + Sync + 'static,
	NodeMetadataProvider: AccessNodeMetadata,
	NodeMetadataProvider::MetadataType: NodeMetadataTrait,
{
	fn decode_and_execute(
		&self,
		context: &IndirectCallsExecutor<
			ShieldingKeyRepository,
			StfEnclaveSigner,
			TopPoolAuthor,
			NodeMetadataProvider,
		>,
		input: &mut &[u8],
	) -> Result<ExecutionStatus<H256>, Error> {
		if let Ok(xt) = self.decode(input) {
			if self.is_target_call(xt.function.clone(), context.node_meta_data_provider.as_ref()) {
				self.execute(context, xt.clone())
					.map(|_| ExecutionStatus::Success(hash_of(&xt)))
			} else {
				Ok(ExecutionStatus::NextExecutor)
			}
		} else {
			Ok(ExecutionStatus::NextExecutor)
		}
	}
}
