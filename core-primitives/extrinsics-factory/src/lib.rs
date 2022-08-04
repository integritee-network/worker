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
use error::Result;
use itp_node_api::metadata::{provider::AccessNodeMetadata, NodeMetadata};
use itp_nonce_cache::{MutateNonce, Nonce};
use itp_types::{OpaqueCall, ParentchainExtrinsicParams, ParentchainExtrinsicParamsBuilder};
use sp_core::{Pair, H256};
use sp_runtime::{generic::Era, MultiSignature, OpaqueExtrinsic};
use std::{sync::Arc, vec::Vec};
use substrate_api_client::{compose_extrinsic_offline, ExtrinsicParams};

pub mod error;

#[cfg(feature = "mocks")]
pub mod mock;

/// Create extrinsics from opaque calls
///
/// Also increases the nonce counter for each extrinsic that is created.
pub trait CreateExtrinsics {
	fn create_extrinsics(
		&self,
		calls: &[OpaqueCall],
		extrinsics_params_builder: Option<ParentchainExtrinsicParamsBuilder>,
	) -> Result<Vec<OpaqueExtrinsic>>;
}

/// Extrinsics factory
pub struct ExtrinsicsFactory<Signer, NonceCache, NodeMetadataRepository>
where
	Signer: Pair<Public = sp_core::ed25519::Public>,
	Signer::Signature: Into<MultiSignature>,
	NonceCache: MutateNonce,
	NodeMetadataRepository: AccessNodeMetadata<MetadataType = NodeMetadata>,
{
	genesis_hash: H256,
	signer: Signer,
	nonce_cache: Arc<NonceCache>,
	node_metadata_repository: Arc<NodeMetadataRepository>,
}

impl<Signer, NonceCache, NodeMetadataRepository>
	ExtrinsicsFactory<Signer, NonceCache, NodeMetadataRepository>
where
	Signer: Pair<Public = sp_core::ed25519::Public>,
	Signer::Signature: Into<MultiSignature>,
	NonceCache: MutateNonce,
	NodeMetadataRepository: AccessNodeMetadata<MetadataType = NodeMetadata>,
{
	pub fn new(
		genesis_hash: H256,
		signer: Signer,
		nonce_cache: Arc<NonceCache>,
		node_metadata_repository: Arc<NodeMetadataRepository>,
	) -> Self {
		ExtrinsicsFactory { genesis_hash, signer, nonce_cache, node_metadata_repository }
	}
}

impl<Signer, NonceCache, NodeMetadataRepository> CreateExtrinsics
	for ExtrinsicsFactory<Signer, NonceCache, NodeMetadataRepository>
where
	Signer: Pair<Public = sp_core::ed25519::Public>,
	Signer::Signature: Into<MultiSignature>,
	NonceCache: MutateNonce,
	NodeMetadataRepository: AccessNodeMetadata<MetadataType = NodeMetadata>,
{
	fn create_extrinsics(
		&self,
		calls: &[OpaqueCall],
		extrinsics_params_builder: Option<ParentchainExtrinsicParamsBuilder>,
	) -> Result<Vec<OpaqueExtrinsic>> {
		let mut nonce_lock = self.nonce_cache.load_for_mutation()?;
		let mut nonce_value = nonce_lock.0;

		let params_builder = extrinsics_params_builder.unwrap_or_else(|| {
			ParentchainExtrinsicParamsBuilder::new()
				.era(Era::Immortal, self.genesis_hash)
				.tip(0)
		});

		let (runtime_spec_version, runtime_transaction_version) =
			self.node_metadata_repository.get_from_metadata(|m| {
				(m.get_runtime_version(), m.get_runtime_transaction_version())
			})?;

		let extrinsics_buffer: Vec<OpaqueExtrinsic> = calls
			.iter()
			.map(|call| {
				let extrinsic_params = ParentchainExtrinsicParams::new(
					runtime_spec_version,
					runtime_transaction_version,
					nonce_value,
					self.genesis_hash,
					params_builder,
				);
				let xt = compose_extrinsic_offline!(self.signer.clone(), call, extrinsic_params)
					.encode();
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
	use itp_node_api::metadata::provider::NodeMetadataRepository;
	use itp_nonce_cache::{GetNonce, Nonce, NonceCache, NonceValue};
	use sp_core::ed25519;
	//use substrate_api_client::extrinsic::xt_primitives::UncheckedExtrinsicV4;

	#[test]
	pub fn creating_xts_increases_nonce_for_each_xt() {
		let nonce_cache = Arc::new(NonceCache::default());
		let node_metadata_repo = Arc::new(NodeMetadataRepository::new(NodeMetadata::default()));
		let extrinsics_factory = ExtrinsicsFactory::new(
			test_genesis_hash(),
			test_account(),
			nonce_cache.clone(),
			node_metadata_repo,
		);

		let opaque_calls = [OpaqueCall(vec![3u8; 42]), OpaqueCall(vec![12u8, 78])];
		let xts = extrinsics_factory.create_extrinsics(&opaque_calls, None).unwrap();

		assert_eq!(opaque_calls.len(), xts.len());
		assert_eq!(nonce_cache.get_nonce().unwrap(), Nonce(opaque_calls.len() as NonceValue));
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

	fn test_genesis_hash() -> H256 {
		H256::from_slice(&[56u8; 32])
	}
}
