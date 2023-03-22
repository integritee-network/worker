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

use sp_core::{Decode, Encode};

pub use sp_runtime::MultiSignature;
pub use substrate_api_client::{
	CallIndex, GenericAddress, PlainTip, PlainTipExtrinsicParams, PlainTipExtrinsicParamsBuilder,
	SubstrateDefaultSignedExtra, UncheckedExtrinsicV4,
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

/// Trait to extract signature and call indexes of an encoded [UncheckedExtrinsicV4].
pub trait ExtractCallIndexAndSignature {
	/// Signed extra of the extrinsic.
	type SignedExtra;

	/// Signature of the extrinsics.
	type Signature;

	fn extract_call_index_and_signature(
		encode_call: &mut &[u8],
	) -> Option<(Self::Signature, CallIndex)>;
}

/// Signature type of the [UncheckedExtrinsicV4].
pub type Signature<SignedExtra> = Option<(GenericAddress, MultiSignature, SignedExtra)>;

impl<Call, SignedExtra> ExtractCallIndexAndSignature for UncheckedExtrinsicV4<Call, SignedExtra>
where
	// The Encode bounds are needed because of erroneous trait bounds in the api-client.
	Call: Decode + Encode,
	SignedExtra: Decode + Encode,
{
	type SignedExtra = SignedExtra;
	type Signature = Signature<Self::SignedExtra>;

	/// Extract a call index of an encoded call.
	///
	/// Note: This mutates the pointer to the slice such that it is past the `signature` and the
	/// `call_index`, which is at the start of the actual parentchain's dispatchable's arguments.
	fn extract_call_index_and_signature(
		encoded_call: &mut &[u8],
	) -> Option<(Self::Signature, CallIndex)> {
		let xt = UncheckedExtrinsicV4::<(CallIndex, ()), Self::SignedExtra>::decode(encoded_call)
			.ok()?;
		Some((xt.signature, xt.function.0))
	}
}

#[cfg(feature = "std")]
pub use api::*;

#[cfg(feature = "std")]
mod api {
	use super::ParentchainExtrinsicParams;
	use substrate_api_client::Api;

	pub use substrate_api_client::{rpc::WsRpcClient, ApiClientError};

	pub type ParentchainApi = Api<sp_core::sr25519::Pair, WsRpcClient, ParentchainExtrinsicParams>;
}
