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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use thiserror_sgx as thiserror;
}

use codec::Encode;
use core::fmt::Debug;
use error::Result;
use itp_node_api::{
	api_client::{
		traits::ExtrinsicParamsAdjustments, ExtrinsicParams, ParentchainAdditionalParams,
		ParentchainExtrinsicParams, SignExtrinsic,
	},
	metadata::{provider::AccessNodeMetadata, NodeMetadata},
};
use itp_nonce_cache::{MutateNonce, Nonce};
use itp_types::{
	parentchain::{AccountId, Hash, Index},
	OpaqueCall,
};
use itp_utils::hex::hex_encode;
use log::trace;
use sp_core::H256;
use sp_runtime::{generic::Era, OpaqueExtrinsic};
use std::{sync::Arc, vec::Vec};
use substrate_api_client::ac_compose_macros::compose_extrinsic_offline;

pub mod error;

#[cfg(feature = "mocks")]
pub mod mock;

/// Create extrinsics from opaque calls
///
/// Also increases the nonce counter for each extrinsic that is created.
pub trait CreateExtrinsics {
	fn create_extrinsics(&self, calls: &[OpaqueCall]) -> Result<Vec<OpaqueExtrinsic>>;
}

/// Extrinsics factory
pub struct ExtrinsicsFactory<
	Signer,
	NonceCache,
	NodeMetadataRepository,
	MyExtrinsicParams,
	MyAdditionalParams,
	MySignedExtra,
	MyAdditionalSigned,
> where
	Signer: SignExtrinsic<AccountId>,
	NonceCache: MutateNonce,
	NodeMetadataRepository: AccessNodeMetadata<MetadataType = NodeMetadata>,
	MyExtrinsicParams: ExtrinsicParams<
		Index,
		Hash,
		AdditionalParams = MyAdditionalParams,
		SignedExtra = MySignedExtra,
		AdditionalSigned = MyAdditionalSigned,
	>,
{
	genesis_hash: H256,
	signer: Signer,
	extrinsic_params: MyExtrinsicParams,
	nonce_cache: Arc<NonceCache>,
	node_metadata_repository: Arc<NodeMetadataRepository>,
}

impl<
		Signer,
		NonceCache,
		NodeMetadataRepository,
		MyExtrinsicParams,
		MyAdditionalParams,
		MySignedExtra,
		MyAdditionalSigned,
	>
	ExtrinsicsFactory<
		Signer,
		NonceCache,
		NodeMetadataRepository,
		MyExtrinsicParams,
		MyAdditionalParams,
		MySignedExtra,
		MyAdditionalSigned,
	> where
	Signer: SignExtrinsic<AccountId>,
	NonceCache: MutateNonce,
	NodeMetadataRepository: AccessNodeMetadata<MetadataType = NodeMetadata>,
	MyExtrinsicParams: Clone
		+ ExtrinsicParams<
			Index,
			Hash,
			AdditionalParams = MyAdditionalParams,
			SignedExtra = MySignedExtra,
			AdditionalSigned = MyAdditionalSigned,
		>,
	MySignedExtra: Encode,
	MyAdditionalSigned: Encode,
{
	pub fn new(
		genesis_hash: H256,
		signer: Signer,
		extrinsic_params: MyExtrinsicParams,
		nonce_cache: Arc<NonceCache>,
		node_metadata_repository: Arc<NodeMetadataRepository>,
	) -> Self {
		ExtrinsicsFactory {
			genesis_hash,
			signer,
			extrinsic_params,
			nonce_cache,
			node_metadata_repository,
		}
	}

	pub fn with_signer(&self, signer: Signer, nonce_cache: Arc<NonceCache>) -> Self {
		ExtrinsicsFactory {
			genesis_hash: self.genesis_hash,
			signer,
			extrinsic_params: self.extrinsic_params.clone(),
			nonce_cache,
			node_metadata_repository: self.node_metadata_repository.clone(),
		}
	}
}

impl<
		Signer,
		NonceCache,
		NodeMetadataRepository,
		MyExtrinsicParams,
		MyAdditionalParams,
		MySignedExtra,
		MyAdditionalSigned,
	> CreateExtrinsics
	for ExtrinsicsFactory<
		Signer,
		NonceCache,
		NodeMetadataRepository,
		MyExtrinsicParams,
		MyAdditionalParams,
		MySignedExtra,
		MyAdditionalSigned,
	> where
	Signer: SignExtrinsic<AccountId>,
	NonceCache: MutateNonce,
	NodeMetadataRepository: AccessNodeMetadata<MetadataType = NodeMetadata>,
	MyExtrinsicParams: Clone
		+ Debug
		+ ExtrinsicParamsAdjustments<MyAdditionalParams>
		+ ExtrinsicParams<
			Index,
			Hash,
			AdditionalParams = MyAdditionalParams,
			SignedExtra = MySignedExtra,
			AdditionalSigned = MyAdditionalSigned,
		>,
	MySignedExtra: Encode + Copy,
	MyAdditionalSigned: Encode + Copy,
{
	fn create_extrinsics(&self, calls: &[OpaqueCall]) -> Result<Vec<OpaqueExtrinsic>> {
		let mut nonce_lock = self.nonce_cache.load_for_mutation()?;
		let mut nonce_value = nonce_lock.0;

		let (runtime_spec_version, runtime_transaction_version) =
			self.node_metadata_repository.get_from_metadata(|m| {
				(m.get_runtime_version(), m.get_runtime_transaction_version())
			})?;

		let mut xt_params = self
			.extrinsic_params
			.with_spec_version(runtime_spec_version)
			.with_transaction_version(runtime_transaction_version);

		let extrinsics_buffer: Vec<OpaqueExtrinsic> = calls
			.iter()
			.map(|call| {
				xt_params = xt_params.with_nonce(nonce_value);
				trace!("create_extrinsic: encoded call: {} ", hex_encode(&call.encode()));
				trace!("   extrinsic params: {:?}", xt_params);
				let xt = compose_extrinsic_offline!(&self.signer, call, xt_params.clone()).encode();
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
}

#[cfg(test)]
pub mod tests {

	use super::*;
	use itp_node_api::{
		api_client::{PairSignature, StaticExtrinsicSigner},
		metadata::provider::NodeMetadataRepository,
	};
	use itp_nonce_cache::{GetNonce, Nonce, NonceCache, NonceValue};
	use sp_core::{ed25519, Pair};
	//use substrate_api_client::extrinsic::xt_primitives::UncheckedExtrinsicV4;

	#[test]
	pub fn creating_xts_increases_nonce_for_each_xt() {
		let nonce_cache = Arc::new(NonceCache::default());
		let node_metadata_repo = Arc::new(NodeMetadataRepository::new(NodeMetadata::default()));
		let extrinsics_factory = ExtrinsicsFactory::new(
			test_genesis_hash(),
			StaticExtrinsicSigner::<_, PairSignature>::new(test_account()),
			nonce_cache.clone(),
			node_metadata_repo,
		);

		let opaque_calls = [OpaqueCall(vec![3u8; 42]), OpaqueCall(vec![12u8, 78])];
		let xts = extrinsics_factory.create_extrinsics(&opaque_calls).unwrap();

		assert_eq!(opaque_calls.len(), xts.len());
		assert_eq!(nonce_cache.get_nonce().unwrap(), Nonce(opaque_calls.len() as NonceValue));
	}

	#[test]
	pub fn with_signer_works() {
		let nonce_cache1 = Arc::new(NonceCache::default());
		*nonce_cache1.load_for_mutation().unwrap() = Nonce(42);

		let node_metadata_repo = Arc::new(NodeMetadataRepository::new(NodeMetadata::default()));
		let extrinsics_factory = ExtrinsicsFactory::new(
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

		let opaque_calls = [OpaqueCall(vec![3u8; 42]), OpaqueCall(vec![12u8, 78])];
		let xts = extrinsics_factory.create_extrinsics(&opaque_calls).unwrap();

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
