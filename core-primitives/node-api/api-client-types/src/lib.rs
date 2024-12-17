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

//! Contains semi-generic type definitions to talk to the node without depending on an implementation of Runtime.
//!
//! You need to update this if you have a signed extension in your node that
//! is different from the integritee-node, e.g., if you use the `pallet_asset_tx_payment`.

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
pub use itp_types::parentchain::{
	AccountData, AccountId, AccountInfo, Address, Balance, Hash, Index, Signature as PairSignature,
};
use scale_info::TypeInfo;
pub use substrate_api_client::{
	ac_node_api::{
		metadata::{InvalidMetadataError, Metadata, MetadataError},
		EventDetails, Events, StaticEvent,
	},
	ac_primitives::{
		config::{AssetRuntimeConfig, Config, DefaultRuntimeConfig},
		extrinsics::{
			CallIndex, ExtrinsicParams, GenericAdditionalParams, GenericAdditionalSigned,
			GenericExtrinsicParams, UncheckedExtrinsicV4,
		},
		serde_impls::StorageKey,
		signer::{SignExtrinsic, StaticExtrinsicSigner},
	},
	rpc::Request,
	storage_key, Api,
};

// traits from the api-client
pub mod traits {
	pub use substrate_api_client::{
		rpc::{Request, Subscribe},
		GetAccountInformation, GetChainInfo, GetStorage,
	};
}

pub type ParentchainPlainTip = PlainTip<Balance>;
pub type ParentchainAssetTip = AssetTip<Balance>;

/// Configuration for the ExtrinsicParams.
///
/// Valid for the default integritee node
pub type ParentchainExtrinsicParams =
	GenericExtrinsicParams<DefaultRuntimeConfig, ParentchainPlainTip>;
pub type ParentchainAdditionalParams = GenericAdditionalParams<ParentchainPlainTip, Hash>;
use sp_runtime::generic::Era;
pub use DefaultRuntimeConfig as ParentchainRuntimeConfig;
// Pay in asset fees.
//
// This needs to be used if the node uses the `pallet_asset_tx_payment`.
//pub type ParentchainExtrinsicParams =  GenericExtrinsicParams<AssetRuntimeConfig, AssetTip>;
// pub type ParentchainAdditionalParams = GenericAdditionalParams<AssetRuntimeConfig, Hash>;

pub type ParentchainUncheckedExtrinsic<Call> =
	UncheckedExtrinsicV4<Address, Call, PairSignature, ParentchainSignedExtra>;
pub type ParentchainSignedExtra = GenericSignedExtra<ParentchainPlainTip, Index>;
pub type ParentchainSignature = Signature<ParentchainSignedExtra>;

/// Signature type of the [UncheckedExtrinsicV4].
pub type Signature<SignedExtra> = Option<(Address, PairSignature, SignedExtra)>;

#[cfg(feature = "std")]
pub use substrate_api_client::{
	api::Error as ApiClientError,
	rpc::{tungstenite_client::TungsteniteRpcClient, Error as RpcClientError},
};

#[derive(Decode, Encode, Copy, Clone, Eq, PartialEq, Debug, TypeInfo)]
pub struct GenericSignedExtra<Tip, Index> {
	pub era: Era,
	#[codec(compact)]
	pub nonce: Index,
	pub tip: Tip,
	pub mode: bool,
}

impl<Tip, Index> GenericSignedExtra<Tip, Index> {
	pub fn new(era: Era, nonce: Index, tip: Tip) -> Self {
		Self { era, nonce, tip, mode: false }
	}
}

#[derive(Copy, Clone, Debug, Default, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct PlainTip<Balance> {
	#[codec(compact)]
	tip: Balance,
}

impl<Balance> PlainTip<Balance> {
	/// Create a new tip of the amount provided.
	pub fn new(amount: Balance) -> Self {
		PlainTip { tip: amount }
	}
}

impl<Balance> From<Balance> for PlainTip<Balance> {
	fn from(n: Balance) -> Self {
		PlainTip::new(n)
	}
}

impl From<PlainTip<u128>> for u128 {
	fn from(tip: PlainTip<u128>) -> Self {
		tip.tip
	}
}

/// Default tip payment for substrate nodes that use the asset payment pallet.
#[derive(Copy, Clone, Debug, Default, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct AssetTip<Balance> {
	#[codec(compact)]
	tip: Balance,
	asset: Option<u32>,
}

impl<Balance> AssetTip<Balance> {
	/// Create a new tip of the amount provided.
	pub fn new(amount: Balance) -> Self {
		AssetTip { tip: amount, asset: None }
	}

	/// Designate the tip as being of a particular asset class.
	/// If this is not set, then the native currency is used.
	pub fn of_asset(mut self, asset: u32) -> Self {
		self.asset = Some(asset);
		self
	}
}

impl<Balance> From<Balance> for AssetTip<Balance> {
	fn from(n: Balance) -> Self {
		AssetTip::new(n)
	}
}

impl From<AssetTip<u128>> for u128 {
	fn from(tip: AssetTip<u128>) -> Self {
		tip.tip
	}
}
