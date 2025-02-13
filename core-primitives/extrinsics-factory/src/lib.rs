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

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

extern crate core;
#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use thiserror_sgx as thiserror;
}

use codec::Encode;
use core::{fmt::Debug, marker::PhantomData};
use error::Result;
use itp_node_api::{
	api_client::{ExtrinsicParams, GenericAdditionalParams, GenericExtrinsicParams, SignExtrinsic},
	metadata::{provider::AccessNodeMetadata, NodeMetadata},
};
use itp_nonce_cache::{MutateNonce, Nonce};
use itp_types::{
	parentchain::{AccountId, GenericMortality},
	OpaqueCall,
};
use sp_core::H256;
use sp_runtime::OpaqueExtrinsic;
use std::{sync::Arc, vec::Vec};
use substrate_api_client::{ac_compose_macros::compose_extrinsic_offline, ac_primitives::Config};

pub mod error;

#[cfg(feature = "mocks")]
pub mod mock;

/// Create extrinsics from opaque calls
///
/// Also increases the nonce counter for each extrinsic that is created.
pub trait CreateExtrinsics {
	type Config: Config;
	type ExtrinsicParams: ExtrinsicParams<
		<Self::Config as Config>::Index,
		<Self::Config as Config>::Hash,
	>;

	fn create_extrinsics(
		&self,
		calls: &[(OpaqueCall, GenericMortality)],
		extrinsics_params: Option<AdditionalParamsOf<Self::Config, Self::ExtrinsicParams>>,
	) -> Result<Vec<OpaqueExtrinsic>>;

	fn genesis_hash(&self) -> H256;
}

pub type AdditionalParamsOf<C, E> =
	<E as ExtrinsicParams<<C as Config>::Index, <C as Config>::Hash>>::AdditionalParams;

/// Extrinsics factory
pub struct ExtrinsicsFactory<Signer, NonceCache, NodeMetadataRepository, NodeRuntimeConfig, Tip> {
	genesis_hash: H256,
	signer: Signer,
	nonce_cache: Arc<NonceCache>,
	pub node_metadata_repository: Arc<NodeMetadataRepository>,
	_phantom: PhantomData<(NodeRuntimeConfig, Tip)>,
}

impl<Signer, NonceCache, NodeMetadataRepository, NodeRuntimeConfig, Tip>
	ExtrinsicsFactory<Signer, NonceCache, NodeMetadataRepository, NodeRuntimeConfig, Tip>
{
	pub fn new(
		genesis_hash: H256,
		signer: Signer,
		nonce_cache: Arc<NonceCache>,
		node_metadata_repository: Arc<NodeMetadataRepository>,
	) -> Self {
		ExtrinsicsFactory {
			genesis_hash,
			signer,
			nonce_cache,
			node_metadata_repository,
			_phantom: Default::default(),
		}
	}

	pub fn with_signer(&self, signer: Signer, nonce_cache: Arc<NonceCache>) -> Self {
		ExtrinsicsFactory {
			genesis_hash: self.genesis_hash,
			signer,
			nonce_cache,
			node_metadata_repository: self.node_metadata_repository.clone(),
			_phantom: Default::default(),
		}
	}
}

impl<Signer, NonceCache, NodeMetadataRepository, NodeRuntimeConfig, Tip> CreateExtrinsics
	for ExtrinsicsFactory<Signer, NonceCache, NodeMetadataRepository, NodeRuntimeConfig, Tip>
where
	Signer: SignExtrinsic<AccountId>,
	NonceCache: MutateNonce,
	NodeMetadataRepository: AccessNodeMetadata<MetadataType = NodeMetadata>,
	NodeRuntimeConfig: Config<Hash = H256>,
	u128: From<Tip>,
	Tip: Copy + Default + Encode + Debug,
{
	type Config = NodeRuntimeConfig;

	type ExtrinsicParams = GenericExtrinsicParams<NodeRuntimeConfig, Tip>;

	fn create_extrinsics(
		&self,
		calls: &[(OpaqueCall, GenericMortality)],
		extrinsics_params: Option<AdditionalParamsOf<Self::Config, Self::ExtrinsicParams>>,
	) -> Result<Vec<OpaqueExtrinsic>> {
		let mut nonce_lock = self.nonce_cache.load_for_mutation()?;
		let mut nonce_value = nonce_lock.0;

		let (runtime_spec_version, runtime_transaction_version) =
			self.node_metadata_repository.get_from_metadata(|m| {
				(m.get_runtime_version(), m.get_runtime_transaction_version())
			})?;

		let extrinsics_buffer: Vec<OpaqueExtrinsic> = calls
			.iter()
			.map(|(call, mortality)| {
				let additional_extrinsic_params = extrinsics_params.unwrap_or_else(|| {
					GenericAdditionalParams::new().era(
						mortality.era,
						mortality.mortality_checkpoint.unwrap_or(self.genesis_hash),
					)
				});
				let extrinsic_params = GenericExtrinsicParams::<NodeRuntimeConfig, Tip>::new(
					runtime_spec_version,
					runtime_transaction_version,
					nonce_value.into(),
					self.genesis_hash,
					additional_extrinsic_params,
				);

				log::trace!(
					"[ExtrinsicsFactory] SignedExtra: {:?}",
					extrinsic_params.signed_extra()
				);
				log::trace!(
					"[ExtrinsicsFactory] AdditionalParams: {:?}",
					extrinsic_params.additional_signed()
				);

				let xt = compose_extrinsic_offline!(&self.signer, call, extrinsic_params).encode();
				nonce_value += 1;
				xt
			})
			.map(|xt| {
				OpaqueExtrinsic::from_bytes(&xt)
					.expect("A previously encoded extrinsic has valid codec; qed.")
			})
			.collect();

		*nonce_lock = Nonce(nonce_value);

		Ok(extrinsics_buffer)
	}

	fn genesis_hash(&self) -> H256 {
		self.genesis_hash
	}
}

#[cfg(test)]
pub mod tests {

	use super::*;
	use itp_node_api::{
		api_client::{AssetRuntimeConfig, PairSignature, StaticExtrinsicSigner},
		metadata::provider::NodeMetadataRepository,
	};
	use itp_nonce_cache::{GetNonce, Nonce, NonceCache, NonceValue};
	use sp_core::{ed25519, Pair};

	#[test]
	pub fn creating_xts_increases_nonce_for_each_xt() {
		let nonce_cache = Arc::new(NonceCache::default());
		let node_metadata_repo = Arc::new(NodeMetadataRepository::new(NodeMetadata::default()));
		let extrinsics_factory = ExtrinsicsFactory::<_, _, _, AssetRuntimeConfig, u128>::new(
			test_genesis_hash(),
			StaticExtrinsicSigner::<_, PairSignature>::new(test_account()),
			nonce_cache.clone(),
			node_metadata_repo,
		);

		let opaque_calls = [
			(OpaqueCall(vec![3u8; 42]), GenericMortality::immortal()),
			(OpaqueCall(vec![12u8, 78]), GenericMortality::immortal()),
		];
		let xts = extrinsics_factory.create_extrinsics(&opaque_calls, None).unwrap();

		assert_eq!(opaque_calls.len(), xts.len());
		assert_eq!(nonce_cache.get_nonce().unwrap(), Nonce(opaque_calls.len() as NonceValue));
	}

	#[test]
	pub fn with_signer_works() {
		let nonce_cache1 = Arc::new(NonceCache::default());
		*nonce_cache1.load_for_mutation().unwrap() = Nonce(42);

		let node_metadata_repo = Arc::new(NodeMetadataRepository::new(NodeMetadata::default()));
		let extrinsics_factory = ExtrinsicsFactory::<_, _, _, AssetRuntimeConfig, u128>::new(
			test_genesis_hash(),
			StaticExtrinsicSigner::<_, PairSignature>::new(test_account()),
			nonce_cache1.clone(),
			node_metadata_repo,
		);

		let nonce_cache2 = Arc::new(NonceCache::default());
		let extrinsics_factory = extrinsics_factory.with_signer(
			StaticExtrinsicSigner::<_, PairSignature>::new(test_account2()),
			nonce_cache2.clone(),
		);
		let opaque_calls = [
			(OpaqueCall(vec![3u8; 42]), GenericMortality::immortal()),
			(OpaqueCall(vec![12u8, 78]), GenericMortality::immortal()),
		];
		let xts = extrinsics_factory.create_extrinsics(&opaque_calls, None).unwrap();

		assert_eq!(opaque_calls.len(), xts.len());
		assert_eq!(nonce_cache2.get_nonce().unwrap(), Nonce(opaque_calls.len() as NonceValue));
		assert_eq!(nonce_cache1.get_nonce().unwrap(), Nonce(42));
	}

	// #[test]
	// pub fn xts_have_increasing_nonce() {
	// 	let nonce_cache = Arc::new(NonceCache::default());
	// 	nonce_cache.set_nonce(Nonce(34)).unwrap();
	// 	let extrinsics_factory =
	// 		ExtrinsicsFactory::new(test_genesis_hash(), test_account(), nonce_cache);
	//
	// 	let opaque_calls =
	// 		[OpaqueCall(vec![3u8; 42]), OpaqueCall(vec![12u8, 78]), OpaqueCall(vec![15u8, 12])];
	// 	let xts: Vec<UncheckedExtrinsicV4<OpaqueCall>> = extrinsics_factory
	// 		.create_extrinsics(&opaque_calls)
	// 		.unwrap()
	// 		.iter()
	// 		.map(|mut x| UncheckedExtrinsicV4::<OpaqueCall>::decode(&mut x))
	// 		.collect();
	//
	// 	assert_eq!(xts.len(), opaque_calls.len());
	// 	assert_eq!(xts[0].signature.unwrap().2 .2, 34u128);
	// }

	fn test_account() -> ed25519::Pair {
		ed25519::Pair::from_seed(b"42315678901234567890123456789012")
	}

	fn test_account2() -> ed25519::Pair {
		ed25519::Pair::from_seed(b"12315678901234567890123456789012")
	}

	fn test_genesis_hash() -> H256 {
		H256::from_slice(&[56u8; 32])
	}
}
