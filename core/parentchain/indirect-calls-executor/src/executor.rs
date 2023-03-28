/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

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
//! Execute indirect calls, i.e. extrinsics extracted from parentchain blocks

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use crate::{
	error::Result,
	filter_calls::FilterCalls,
	traits::{ExecuteIndirectCalls, IndirectDispatch, IndirectExecutor},
};
use binary_merkle_tree::merkle_root;
use codec::Encode;
use core::marker::PhantomData;
use ita_stf::{TrustedCall, TrustedCallSigned};
use itp_node_api::metadata::{
	pallet_teerex::TeerexCallIndexes, provider::AccessNodeMetadata, NodeMetadataTrait,
};
use itp_sgx_crypto::{key_repository::AccessKey, ShieldingCryptoDecrypt, ShieldingCryptoEncrypt};
use itp_stf_executor::traits::StfEnclaveSigning;
use itp_stf_primitives::types::AccountId;
use itp_top_pool_author::traits::AuthorApi;
use itp_types::{OpaqueCall, ShardIdentifier, H256};
use log::*;
use sp_core::blake2_256;
use sp_runtime::traits::{Block as ParentchainBlockTrait, Header, Keccak256};
use std::{sync::Arc, vec::Vec};

pub struct IndirectCallsExecutor<
	ShieldingKeyRepository,
	StfEnclaveSigner,
	TopPoolAuthor,
	NodeMetadataProvider,
	IndirectCallsFilter,
> {
	pub(crate) shielding_key_repo: Arc<ShieldingKeyRepository>,
	pub(crate) stf_enclave_signer: Arc<StfEnclaveSigner>,
	pub(crate) top_pool_author: Arc<TopPoolAuthor>,
	pub(crate) node_meta_data_provider: Arc<NodeMetadataProvider>,
	_phantom: PhantomData<IndirectCallsFilter>,
}
impl<
		ShieldingKeyRepository,
		StfEnclaveSigner,
		TopPoolAuthor,
		NodeMetadataProvider,
		IndirectCallsFilter,
	>
	IndirectCallsExecutor<
		ShieldingKeyRepository,
		StfEnclaveSigner,
		TopPoolAuthor,
		NodeMetadataProvider,
		IndirectCallsFilter,
	>
{
	pub fn new(
		shielding_key_repo: Arc<ShieldingKeyRepository>,
		stf_enclave_signer: Arc<StfEnclaveSigner>,
		top_pool_author: Arc<TopPoolAuthor>,
		node_meta_data_provider: Arc<NodeMetadataProvider>,
	) -> Self {
		IndirectCallsExecutor {
			shielding_key_repo,
			stf_enclave_signer,
			top_pool_author,
			node_meta_data_provider,
			_phantom: Default::default(),
		}
	}
}

impl<
		ShieldingKeyRepository,
		StfEnclaveSigner,
		TopPoolAuthor,
		NodeMetadataProvider,
		FilterIndirectCalls,
	> ExecuteIndirectCalls
	for IndirectCallsExecutor<
		ShieldingKeyRepository,
		StfEnclaveSigner,
		TopPoolAuthor,
		NodeMetadataProvider,
		FilterIndirectCalls,
	> where
	ShieldingKeyRepository: AccessKey,
	<ShieldingKeyRepository as AccessKey>::KeyType: ShieldingCryptoDecrypt<Error = itp_sgx_crypto::Error>
		+ ShieldingCryptoEncrypt<Error = itp_sgx_crypto::Error>,
	StfEnclaveSigner: StfEnclaveSigning,
	TopPoolAuthor: AuthorApi<H256, H256> + Send + Sync + 'static,
	NodeMetadataProvider: AccessNodeMetadata,
	NodeMetadataProvider::MetadataType: NodeMetadataTrait,
	FilterIndirectCalls: FilterCalls<NodeMetadataProvider::MetadataType>,
	FilterIndirectCalls::Call: IndirectDispatch<Self> + Encode,
{
	fn execute_indirect_calls_in_extrinsics<ParentchainBlock>(
		&self,
		block: &ParentchainBlock,
	) -> Result<OpaqueCall>
	where
		ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	{
		let block_number = *block.header().number();
		let block_hash = block.hash();

		debug!("Scanning block {:?} for relevant xt", block_number);
		let mut executed_calls = Vec::<H256>::new();

		for xt_opaque in block.extrinsics().iter() {
			let encoded_xt_opaque = xt_opaque.encode();

			let maybe_call = self.node_meta_data_provider.get_from_metadata(|metadata| {
				FilterIndirectCalls::filter_into_with_metadata(&encoded_xt_opaque, metadata)
			})?;

			let call = match maybe_call {
				Some(c) => c,
				None => continue,
			};

			if let Err(e) = call.dispatch(self) {
				log::warn!("Error executing the indirect call: {:?}", e);
				continue
			};

			executed_calls.push(hash_of(&call))
		}

		// Include a processed parentchain block confirmation for each block.
		self.create_processed_parentchain_block_call::<ParentchainBlock>(
			block_hash,
			executed_calls,
			block_number,
		)
	}

	fn create_processed_parentchain_block_call<ParentchainBlock>(
		&self,
		block_hash: H256,
		extrinsics: Vec<H256>,
		block_number: <<ParentchainBlock as ParentchainBlockTrait>::Header as Header>::Number,
	) -> Result<OpaqueCall>
	where
		ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	{
		let call = self.node_meta_data_provider.get_from_metadata(|meta_data| {
			meta_data.confirm_processed_parentchain_block_call_indexes()
		})??;

		let root: H256 = merkle_root::<Keccak256, _>(extrinsics);
		Ok(OpaqueCall::from_tuple(&(call, block_hash, block_number, root)))
	}
}

impl<
		ShieldingKeyRepository,
		StfEnclaveSigner,
		TopPoolAuthor,
		NodeMetadataProvider,
		FilterIndirectCalls,
	> IndirectExecutor
	for IndirectCallsExecutor<
		ShieldingKeyRepository,
		StfEnclaveSigner,
		TopPoolAuthor,
		NodeMetadataProvider,
		FilterIndirectCalls,
	> where
	ShieldingKeyRepository: AccessKey,
	<ShieldingKeyRepository as AccessKey>::KeyType: ShieldingCryptoDecrypt<Error = itp_sgx_crypto::Error>
		+ ShieldingCryptoEncrypt<Error = itp_sgx_crypto::Error>,
	StfEnclaveSigner: StfEnclaveSigning,
	TopPoolAuthor: AuthorApi<H256, H256> + Send + Sync + 'static,
{
	fn submit_trusted_call(&self, shard: ShardIdentifier, encrypted_trusted_call: Vec<u8>) {
		if let Err(e) = futures::executor::block_on(
			self.top_pool_author.submit_top(encrypted_trusted_call, shard),
		) {
			error!("Error adding indirect trusted call to TOP pool: {:?}", e);
		}
	}

	fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
		let key = self.shielding_key_repo.retrieve_key()?;
		Ok(key.decrypt(encrypted)?)
	}

	fn encrypt(&self, value: &[u8]) -> Result<Vec<u8>> {
		let key = self.shielding_key_repo.retrieve_key()?;
		Ok(key.encrypt(value)?)
	}

	fn get_enclave_account(&self) -> Result<AccountId> {
		Ok(self.stf_enclave_signer.get_enclave_account()?)
	}

	fn sign_call_with_self(
		&self,
		trusted_call: &TrustedCall,
		shard: &ShardIdentifier,
	) -> Result<TrustedCallSigned> {
		Ok(self.stf_enclave_signer.sign_call_with_self(trusted_call, shard)?)
	}
}

pub(crate) fn hash_of<T: Encode>(xt: &T) -> H256 {
	blake2_256(&xt.encode()).into()
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		filter_calls::ShieldFundsAndCallWorkerFilter,
		parentchain_extrinsic_parser::ParentchainExtrinsicParser,
	};
	use codec::{Decode, Encode};
	use ita_stf::TrustedOperation;
	use itc_parentchain_test::parentchain_block_builder::ParentchainBlockBuilder;
	use itp_node_api::{
		api_client::{
			ParentchainExtrinsicParams, ParentchainExtrinsicParamsBuilder,
			ParentchainUncheckedExtrinsic,
		},
		metadata::{metadata_mocks::NodeMetadataMock, provider::NodeMetadataRepository},
	};
	use itp_sgx_crypto::mocks::KeyRepositoryMock;
	use itp_stf_executor::mocks::StfEnclaveSignerMock;
	use itp_stf_primitives::types::AccountId;
	use itp_test::mock::shielding_crypto_mock::ShieldingCryptoMock;
	use itp_top_pool_author::mocks::AuthorApiMock;
	use itp_types::{Block, CallWorkerFn, Request, ShardIdentifier, ShieldFundsFn};
	use sp_core::{ed25519, Pair};
	use sp_runtime::{MultiSignature, OpaqueExtrinsic};
	use std::assert_matches::assert_matches;
	use substrate_api_client::{ExtrinsicParams, GenericAddress};

	type TestShieldingKeyRepo = KeyRepositoryMock<ShieldingCryptoMock>;
	type TestStfEnclaveSigner = StfEnclaveSignerMock;
	type TestTopPoolAuthor = AuthorApiMock<H256, H256>;
	type TestNodeMetadataRepository = NodeMetadataRepository<NodeMetadataMock>;
	type TestIndirectCallExecutor = IndirectCallsExecutor<
		TestShieldingKeyRepo,
		TestStfEnclaveSigner,
		TestTopPoolAuthor,
		TestNodeMetadataRepository,
		ShieldFundsAndCallWorkerFilter<ParentchainExtrinsicParser>,
	>;

	type Seed = [u8; 32];
	const TEST_SEED: Seed = *b"12345678901234567890123456789012";

	#[test]
	fn indirect_call_can_be_added_to_pool_successfully() {
		let _ = env_logger::builder().is_test(true).try_init();

		let (indirect_calls_executor, top_pool_author, _) =
			test_fixtures([0u8; 32], NodeMetadataMock::new());

		let opaque_extrinsic =
			OpaqueExtrinsic::from_bytes(call_worker_unchecked_extrinsic().encode().as_slice())
				.unwrap();

		let parentchain_block = ParentchainBlockBuilder::default()
			.with_extrinsics(vec![opaque_extrinsic])
			.build();

		indirect_calls_executor
			.execute_indirect_calls_in_extrinsics(&parentchain_block)
			.unwrap();

		assert_eq!(1, top_pool_author.pending_tops(shard_id()).unwrap().len());
	}

	#[test]
	fn shielding_call_can_be_added_to_pool_successfully() {
		let _ = env_logger::builder().is_test(true).try_init();

		let mr_enclave = [33u8; 32];
		let (indirect_calls_executor, top_pool_author, shielding_key_repo) =
			test_fixtures(mr_enclave.clone(), NodeMetadataMock::new());
		let shielding_key = shielding_key_repo.retrieve_key().unwrap();

		let opaque_extrinsic = OpaqueExtrinsic::from_bytes(
			shield_funds_unchecked_extrinsic(&shielding_key).encode().as_slice(),
		)
		.unwrap();

		let parentchain_block = ParentchainBlockBuilder::default()
			.with_extrinsics(vec![opaque_extrinsic])
			.build();

		indirect_calls_executor
			.execute_indirect_calls_in_extrinsics(&parentchain_block)
			.unwrap();

		assert_eq!(1, top_pool_author.pending_tops(shard_id()).unwrap().len());
		let submitted_extrinsic =
			top_pool_author.pending_tops(shard_id()).unwrap().first().cloned().unwrap();
		let decrypted_extrinsic = shielding_key.decrypt(&submitted_extrinsic).unwrap();
		let decoded_operation =
			TrustedOperation::decode(&mut decrypted_extrinsic.as_slice()).unwrap();
		assert_matches!(decoded_operation, TrustedOperation::indirect_call(_));
		let trusted_call_signed = decoded_operation.to_call().unwrap();
		assert!(trusted_call_signed.verify_signature(&mr_enclave, &shard_id()));
	}

	#[test]
	fn ensure_empty_extrinsic_vec_triggers_zero_filled_merkle_root() {
		// given
		let dummy_metadata = NodeMetadataMock::new();
		let (indirect_calls_executor, _, _) = test_fixtures([38u8; 32], dummy_metadata.clone());

		let block_hash = H256::from([1; 32]);
		let extrinsics = Vec::new();
		let confirm_processed_parentchain_block_indexes =
			dummy_metadata.confirm_processed_parentchain_block_call_indexes().unwrap();
		let expected_call =
			(confirm_processed_parentchain_block_indexes, block_hash, 1, H256::default()).encode();

		// when
		let call = indirect_calls_executor
			.create_processed_parentchain_block_call::<Block>(block_hash, extrinsics, 1)
			.unwrap();

		// then
		assert_eq!(call.0, expected_call);
	}

	#[test]
	fn ensure_non_empty_extrinsic_vec_triggers_non_zero_merkle_root() {
		// given
		let dummy_metadata = NodeMetadataMock::new();
		let (indirect_calls_executor, _, _) = test_fixtures([39u8; 32], dummy_metadata.clone());

		let block_hash = H256::from([1; 32]);
		let extrinsics = vec![H256::from([4; 32]), H256::from([9; 32])];
		let confirm_processed_parentchain_block_indexes =
			dummy_metadata.confirm_processed_parentchain_block_call_indexes().unwrap();

		let zero_root_call =
			(confirm_processed_parentchain_block_indexes, block_hash, 1, H256::default()).encode();

		// when
		let call = indirect_calls_executor
			.create_processed_parentchain_block_call::<Block>(block_hash, extrinsics, 1)
			.unwrap();

		// then
		assert_ne!(call.0, zero_root_call);
	}

	fn shield_funds_unchecked_extrinsic(
		shielding_key: &ShieldingCryptoMock,
	) -> ParentchainUncheckedExtrinsic<ShieldFundsFn> {
		let target_account = shielding_key.encrypt(&AccountId::new([2u8; 32]).encode()).unwrap();
		let dummy_metadata = NodeMetadataMock::new();

		let shield_funds_indexes = dummy_metadata.shield_funds_call_indexes().unwrap();
		ParentchainUncheckedExtrinsic::<ShieldFundsFn>::new_signed(
			(shield_funds_indexes, target_account, 1000u128, shard_id()),
			GenericAddress::Address32([1u8; 32]),
			MultiSignature::Ed25519(default_signature()),
			default_extrinsic_params().signed_extra(),
		)
	}

	fn call_worker_unchecked_extrinsic() -> ParentchainUncheckedExtrinsic<CallWorkerFn> {
		let request = Request { shard: shard_id(), cyphertext: vec![1u8, 2u8] };
		let dummy_metadata = NodeMetadataMock::new();
		let call_worker_indexes = dummy_metadata.call_worker_call_indexes().unwrap();

		ParentchainUncheckedExtrinsic::<CallWorkerFn>::new_signed(
			(call_worker_indexes, request),
			GenericAddress::Address32([1u8; 32]),
			MultiSignature::Ed25519(default_signature()),
			default_extrinsic_params().signed_extra(),
		)
	}

	fn default_signature() -> ed25519::Signature {
		signer().sign(&[0u8])
	}

	fn signer() -> ed25519::Pair {
		ed25519::Pair::from_seed(&TEST_SEED)
	}

	fn shard_id() -> ShardIdentifier {
		ShardIdentifier::default()
	}

	fn default_extrinsic_params() -> ParentchainExtrinsicParams {
		ParentchainExtrinsicParams::new(
			0,
			0,
			0,
			H256::default(),
			ParentchainExtrinsicParamsBuilder::default(),
		)
	}
	fn test_fixtures(
		mr_enclave: [u8; 32],
		metadata: NodeMetadataMock,
	) -> (TestIndirectCallExecutor, Arc<TestTopPoolAuthor>, Arc<TestShieldingKeyRepo>) {
		let shielding_key_repo = Arc::new(TestShieldingKeyRepo::default());
		let stf_enclave_signer = Arc::new(TestStfEnclaveSigner::new(mr_enclave));
		let top_pool_author = Arc::new(TestTopPoolAuthor::default());
		let node_metadata_repo = Arc::new(NodeMetadataRepository::new(metadata));

		let executor = IndirectCallsExecutor::new(
			shielding_key_repo.clone(),
			stf_enclave_signer,
			top_pool_author.clone(),
			node_metadata_repo,
		);

		(executor, top_pool_author, shielding_key_repo)
	}
}
