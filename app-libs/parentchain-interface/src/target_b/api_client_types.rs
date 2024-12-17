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

use crate::{
	AssetTip, GenericAdditionalParams, GenericExtrinsicParams, GenericSignedExtra,
	ParentchainRuntimeConfig, UncheckedExtrinsicV4,
};
pub use itp_types::parentchain::{
	AccountData, AccountId, AccountInfo, Address, Balance, Hash, Header, Index,
	Signature as PairSignature,
};
use sp_runtime::generic;

pub type TargetBRuntimeConfig = ParentchainRuntimeConfig<TargetBTip>;

// Configuration for the ExtrinsicParams.

// Using the AssetTip, as we assume that TargetB uses the `pallet_asset_tx_payment`.
pub type TargetBTip = AssetTip<Balance>;
pub type TargetBExtrinsicParams = GenericExtrinsicParams<TargetBRuntimeConfig, TargetBTip>;
pub type TargetBAdditionalParams = GenericAdditionalParams<TargetBRuntimeConfig, Hash>;

pub type TargetBSignedExtra = GenericSignedExtra<TargetBTip, Index>;
pub type TargetBSignature = Signature<TargetBSignedExtra>;

pub type TargetBUncheckedExtrinsic<Call> =
	UncheckedExtrinsicV4<Address, Call, PairSignature, TargetBSignedExtra>;

/// Signature type of the [UncheckedExtrinsicV4].
pub type Signature<SignedExtra> = Option<(Address, PairSignature, SignedExtra)>;
pub type Block = generic::Block<Header, TargetBUncheckedExtrinsic<([u8; 2])>>;
pub type SignedBlock = generic::SignedBlock<Block>;

#[cfg(feature = "std")]
pub use api::*;

#[cfg(feature = "std")]
mod api {
	use super::TargetBRuntimeConfig;
	use substrate_api_client::Api;
	pub use substrate_api_client::{
		api::Error as ApiClientError,
		rpc::{tungstenite_client::TungsteniteRpcClient, Error as RpcClientError},
	};

	pub type TargetBApi = Api<TargetBRuntimeConfig, TungsteniteRpcClient>;
}
