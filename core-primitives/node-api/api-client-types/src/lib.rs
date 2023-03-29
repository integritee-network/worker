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

pub use itp_types::parentchain::{Balance, Index};
pub use sp_runtime::MultiSignature;
pub use substrate_api_client::{
	CallIndex, GenericAddress, PlainTip, PlainTipExtrinsicParams, PlainTipExtrinsicParamsBuilder,
	SubstrateDefaultSignedExtra, UncheckedExtrinsicV4,
};

/// Configuration for the ExtrinsicParams.
///
/// Valid for the default integritee node
pub type ParentchainExtrinsicParams<Runtime> = PlainTipExtrinsicParams<Runtime>;
pub type ParentchainExtrinsicParamsBuilder<Runtime> = PlainTipExtrinsicParamsBuilder<Runtime>;

// Pay in asset fees.
//
// This needs to be used if the node uses the `pallet_asset_tx_payment`.
//pub type ParentchainExtrinsicParams<Runtime> = AssetTipExtrinsicParams<Runtime>;
//pub type ParentchainExtrinsicParamsBuilder<Runtime> = AssetTipExtrinsicParamsBuilder<Runtime>;

pub type ParentchainUncheckedExtrinsic<Call> = UncheckedExtrinsicV4<Call, ParentchainSignedExtra>;
pub type ParentchainSignedExtra = SubstrateDefaultSignedExtra<PlainTip<Balance>, Index>;
pub type ParentchainSignature = Signature<ParentchainSignedExtra>;

/// Signature type of the [UncheckedExtrinsicV4].
pub type Signature<SignedExtra> = Option<(GenericAddress, MultiSignature, SignedExtra)>;

#[cfg(feature = "std")]
pub use api::*;

#[cfg(feature = "std")]
mod api {
	use super::ParentchainExtrinsicParams;
	use substrate_api_client::Api;

	pub use my_node_runtime::Runtime;
	pub use substrate_api_client::{api::Error as ApiClientError, rpc::WsRpcClient,  rpc::Error as RpcClientError};

	pub type ParentchainApi =
		Api<sp_core::sr25519::Pair, WsRpcClient, ParentchainExtrinsicParams<Runtime>, Runtime>;
}
