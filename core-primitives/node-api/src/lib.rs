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

//! All kind of things to talk to a node.

//! Contains type definitions to talk to the node.
///
/// For example, you need to update this if you have a signed extensions in your node that
/// is different from the integritee-node, or if you use the `pallet_asset_tx_payment`.
use substrate_api_client::{
	PlainTip, PlainTipExtrinsicParams, PlainTipExtrinsicParamsBuilder, SubstrateDefaultSignedExtra,
	UncheckedExtrinsicV4,
};

/// Configuration for the ExtrinsicParams.
///
/// Valid for the default integritee node
pub type ParentchainExtrinsicParams = PlainTipExtrinsicParams;
pub type ParentchainExtrinsicParamsBuilder = PlainTipExtrinsicParamsBuilder;

// Pay in asset fees.
//
// This needs to be used if the node uses the `pallet_asset_tx_payment`.
//pub type ParentchainExtrinsicParams = AssetTipExtrinsicParams;
//pub type ParentchainExtrinsicParamsBuilder = AssetTipExtrinsicParamsBuilder;

pub type ParentchainUncheckedExtrinsic<Call> =
	UncheckedExtrinsicV4<Call, SubstrateDefaultSignedExtra<PlainTip>>;

#[cfg(feature = "std")]
pub use api::*;

#[cfg(feature = "std")]
mod api {
	use super::ParentchainExtrinsicParams;
	use substrate_api_client::{rpc::WsRpcClient, Api};

	pub type ParentchainApi = Api<sp_core::sr25519::Pair, WsRpcClient, ParentchainExtrinsicParams>;
}
