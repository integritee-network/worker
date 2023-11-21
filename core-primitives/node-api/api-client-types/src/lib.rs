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

//! Contains type definitions to talk to the node.
//!
//! You need to update this if you have a signed extension in your node that
//! is different from the integritee-node, e.g., if you use the `pallet_asset_tx_payment`.

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
pub use itp_types::parentchain::{
	AccountData, AccountId, AccountInfo, Address, Balance, Hash, Index, Signature as PairSignature,
};
pub use substrate_api_client::{
	ac_node_api::{
		metadata::{InvalidMetadataError, Metadata, MetadataError},
		EventDetails, Events, StaticEvent,
	},
	ac_primitives::{
		config::{AssetRuntimeConfig, Config, DefaultRuntimeConfig},
		extrinsics::{
			AssetTip, CallIndex, ExtrinsicParams, GenericAdditionalParams, GenericAdditionalSigned,
			GenericExtrinsicParams, GenericSignedExtra, PlainTip, UncheckedExtrinsicV4,
		},
		serde_impls::StorageKey,
		signer::{SignExtrinsic, StaticExtrinsicSigner},
	},
	rpc::Request,
	storage_key, Api,
};

// traits from the api-client
pub mod traits {
	use itp_types::parentchain::Index;
	pub use substrate_api_client::{GetAccountInformation, GetChainInfo, GetStorage};

	pub trait ExtrinsicParamsAdjustments<AdditionalParams> {
		fn with_nonce(&self, nonce: Index) -> Self;
		fn with_additional_params(&self, additional_params: AdditionalParams) -> Self;
		fn with_spec_version(&self, version: u32) -> Self;
		fn with_transaction_version(&self, version: u32) -> Self;
	}
}

/// Configuration for the ExtrinsicParams.
///
/// Valid for the default integritee node
#[derive(Decode, Encode, Clone, Eq, PartialEq, Debug)]
pub struct ParentchainExtrinsicParams {
	era: Era,
	nonce: Index,
	tip: ParentchainTip,
	spec_version: u32,
	transaction_version: u32,
	genesis_hash: Hash,
	mortality_checkpoint: Hash,
}

pub type ParentchainAdditionalSigned = GenericAdditionalSigned<Hash>;

pub type ParentchainTip = PlainTip<Balance>;
// in case integritee would use the  `pallet_asset_tx_payment`.
//pub type ParentchainTip = AssetTip<Balance>

impl ExtrinsicParams<Index, Hash> for ParentchainExtrinsicParams {
	type AdditionalParams = ParentchainAdditionalParams;
	type SignedExtra = ParentchainSignedExtra;
	type AdditionalSigned = ParentchainAdditionalSigned;

	fn new(
		spec_version: u32,
		transaction_version: u32,
		nonce: Index,
		genesis_hash: Hash,
		additional_params: Self::AdditionalParams,
	) -> Self {
		Self {
			era: additional_params.era,
			tip: additional_params.tip,
			spec_version,
			transaction_version,
			genesis_hash,
			mortality_checkpoint: additional_params.mortality_checkpoint.unwrap_or(genesis_hash),
			nonce,
		}
	}

	fn signed_extra(&self) -> Self::SignedExtra {
		Self::SignedExtra { era: self.era, nonce: self.nonce, tip: self.tip }
	}

	fn additional_signed(&self) -> Self::AdditionalSigned {
		(
			(),
			self.spec_version,
			self.transaction_version,
			self.genesis_hash,
			self.mortality_checkpoint,
			(),
			(),
			(),
		)
	}
}

impl ExtrinsicParamsAdjustments<ParentchainAdditionalParams> for ParentchainExtrinsicParams {
	fn with_nonce(&self, nonce: Index) -> Self {
		Self {
			era: self.era,
			tip: self.tip,
			spec_version: self.spec_version,
			transaction_version: self.transaction_version,
			genesis_hash: self.genesis_hash,
			mortality_checkpoint: self.mortality_checkpoint,
			nonce,
		}
	}
	fn with_additional_params(&self, additional_params: ParentchainAdditionalParams) -> Self {
		Self {
			era: additional_params.era,
			tip: additional_params.tip,
			spec_version: self.spec_version,
			transaction_version: self.transaction_version,
			genesis_hash: self.genesis_hash,
			mortality_checkpoint: additional_params
				.mortality_checkpoint
				.unwrap_or(self.genesis_hash),
			nonce: self.nonce,
		}
	}
	fn with_spec_version(&self, spec_version: u32) -> Self {
		Self {
			era: self.era,
			tip: self.tip,
			spec_version,
			transaction_version: self.transaction_version,
			genesis_hash: self.genesis_hash,
			mortality_checkpoint: self.mortality_checkpoint,
			nonce: self.nonce,
		}
	}
	fn with_transaction_version(&self, transaction_version: u32) -> Self {
		Self {
			era: self.era,
			tip: self.tip,
			spec_version: self.spec_version,
			transaction_version,
			genesis_hash: self.genesis_hash,
			mortality_checkpoint: self.mortality_checkpoint,
			nonce: self.nonce,
		}
	}
}

#[derive(Decode, Encode, Copy, Clone, Eq, PartialEq, Debug)]
pub struct ParentchainAdditionalParams {
	era: Era,
	mortality_checkpoint: Option<Hash>,
	tip: ParentchainTip,
}

impl Default for ParentchainAdditionalParams {
	fn default() -> Self {
		Self { era: Era::Immortal, mortality_checkpoint: None, tip: ParentchainTip::default() }
	}
}
use sp_runtime::generic::Era;
use substrate_api_client::ac_primitives::WithExtrinsicParams;

/// Standard runtime config for Substrate and Polkadot nodes.
pub type ParentchainPlainTipRuntimeConfig =
	WithExtrinsicParams<AssetRuntimeConfig, PlainTipExtrinsicParams<AssetRuntimeConfig>>;

/// runtime config for chains like Asset Hub or Encointer
pub type ParentchainAssetTipRuntimeConfig =
	WithExtrinsicParams<AssetRuntimeConfig, AssetTipExtrinsicParams<AssetRuntimeConfig>>;

/// A struct representing the signed extra and additional parameters required
/// to construct a transaction and pay in token fees.
pub type PlainTipExtrinsicParams<T> = GenericExtrinsicParams<T, PlainTip<<T as Config>::Balance>>;
pub type AssetTipExtrinsicParams<T> = GenericExtrinsicParams<T, AssetTip<<T as Config>::Balance>>;

pub type ParentchainUncheckedExtrinsic<Call> =
	UncheckedExtrinsicV4<Address, Call, PairSignature, ParentchainSignedExtra>;
pub type ParentchainSignedExtra = GenericSignedExtra<ParentchainTip, Index>;
pub type ParentchainSignature = Signature<ParentchainSignedExtra>;

/// Signature type of the [UncheckedExtrinsicV4].
pub type Signature<SignedExtra> = Option<(Address, PairSignature, SignedExtra)>;

use crate::traits::ExtrinsicParamsAdjustments;
#[cfg(feature = "std")]
pub use api::*;

#[cfg(feature = "std")]
mod api {
	use super::{ParentchainAssetTipRuntimeConfig, ParentchainPlainTipRuntimeConfig};
	use sp_runtime::generic::SignedBlock as GenericSignedBlock;
	use substrate_api_client::Api;

	// We should probably switch to the opaque block, then we can get rid of the
	// runtime dependency here.
	// pub use itp_types::Block;
	pub use my_node_runtime::{Block, Runtime, UncheckedExtrinsic};

	pub use substrate_api_client::{
		api::Error as ApiClientError,
		rpc::{tungstenite_client::TungsteniteRpcClient, Error as RpcClientError},
	};

	pub type SignedBlock = GenericSignedBlock<Block>;

	pub type ParentchainPlainTipApi = Api<ParentchainPlainTipRuntimeConfig, TungsteniteRpcClient>;
	pub type ParentchainAssetTipApi = Api<ParentchainAssetTipRuntimeConfig, TungsteniteRpcClient>;
}
