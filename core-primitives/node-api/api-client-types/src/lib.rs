//! Contains type definitions to talk to the node.
//!
//! For example, you need to update this if you have a signed extensions in your node that
//! is different from the integritee-node, or if you use the `pallet_asset_tx_payment`.

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
pub use api::ParentchainApi;

#[cfg(feature = "std")]
mod api {
	use super::ParentchainExtrinsicParams;
	use substrate_api_client::{rpc::WsRpcClient, Api};

	pub type ParentchainApi = Api<sp_core::sr25519::Pair, WsRpcClient, ParentchainExtrinsicParams>;
}
