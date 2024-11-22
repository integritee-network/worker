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
