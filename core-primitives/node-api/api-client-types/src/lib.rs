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

pub use itp_types::parentchain::{
	AccountId, Address, Balance, Hash, Index, Signature as PairSignature,
};
pub use substrate_api_client::{
	storage_key, AssetTip, CallIndex, EventDetails, Events, ExtrinsicParams,
	GenericAdditionalParams, GenericExtrinsicParams, GenericSignedExtra, InvalidMetadataError,
	Metadata, MetadataError, PlainTip, StaticEvent, StaticExtrinsicSigner, UncheckedExtrinsicV4,
};

pub type ParentchainPlainTip = PlainTip<Balance>;
pub type ParentchainAssetTip = AssetTip<Balance>;

/// Configuration for the ExtrinsicParams.
///
/// Valid for the default integritee node
pub type ParentchainExtrinsicParams = GenericExtrinsicParams<ParentchainPlainTip, Index, Hash>;
pub type ParentchainAdditionalParams = GenericAdditionalParams<ParentchainPlainTip, Hash>;

// Pay in asset fees.
//
// This needs to be used if the node uses the `pallet_asset_tx_payment`.
//pub type ParentchainExtrinsicParams =  GenericExtrinsicParams<ParentchainAssetTip, Index, Hash>;
// pub type ParentchainAdditionalParams = GenericAdditionalParams<ParentchainAssetTip, Hash>;

pub type ParentchainUncheckedExtrinsic<Call> =
	UncheckedExtrinsicV4<Address, Call, PairSignature, ParentchainSignedExtra>;
pub type ParentchainSignedExtra = GenericSignedExtra<ParentchainPlainTip, Index>;
pub type ParentchainSignature = Signature<ParentchainSignedExtra>;

/// Signature type of the [UncheckedExtrinsicV4].
pub type Signature<SignedExtra> = Option<(Address, PairSignature, SignedExtra)>;

#[cfg(feature = "std")]
pub use api::*;

#[cfg(feature = "std")]
mod api {
	use super::{PairSignature, ParentchainExtrinsicParams, StaticExtrinsicSigner};
	use sp_runtime::generic::SignedBlock as GenericSignedBlock;
	use substrate_api_client::Api;

	pub use my_node_runtime::{Block, Runtime, UncheckedExtrinsic};

	pub use substrate_api_client::{
		api::Error as ApiClientError,
		rpc::{Error as RpcClientError, WsRpcClient},
	};

	pub type SignedBlock = GenericSignedBlock<Block>;
	pub type ParentchainExtrinsicSigner =
		StaticExtrinsicSigner<sp_core::sr25519::Pair, PairSignature>;

	pub type ParentchainApi =
		Api<ParentchainExtrinsicSigner, WsRpcClient, ParentchainExtrinsicParams, Runtime>;
}
