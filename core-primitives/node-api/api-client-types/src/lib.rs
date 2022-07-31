//! Contains type definitions to talk to the node.
//!
//! You need to update this if you have a signed extension in your node that
//! is different from the integritee-node, e.g., if you use the `pallet_asset_tx_payment`.

#![cfg_attr(not(feature = "std"), no_std)]

pub use substrate_api_client::{
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
	use substrate_api_client::Api;

	pub use substrate_api_client::{rpc::WsRpcClient, ApiClientError};

	pub type ParentchainApi = Api<sp_core::sr25519::Pair, WsRpcClient, ParentchainExtrinsicParams>;
}
