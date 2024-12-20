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
	GenericAdditionalParams, GenericExtrinsicParams, GenericSignedExtra, ParentchainRuntimeConfig,
	PlainTip, UncheckedExtrinsicV4,
};
use itp_types::parentchain::Header;
pub use itp_types::parentchain::{
	AccountData, AccountId, AccountInfo, Address, Balance, Hash, Index, Signature as PairSignature,
};
use sp_runtime::generic;

pub type IntegriteeRuntimeConfig = ParentchainRuntimeConfig<IntegriteeTip>;

// Configuration for the ExtrinsicParams.
pub type IntegriteeTip = PlainTip<Balance>;
pub type IntegriteeExtrinsicParams = GenericExtrinsicParams<IntegriteeRuntimeConfig, IntegriteeTip>;
pub type IntegriteeAdditionalParams = GenericAdditionalParams<IntegriteeRuntimeConfig, Hash>;

pub type IntegriteeSignedExtra = GenericSignedExtra<IntegriteeTip, Index>;
pub type IntegriteeSignature = Signature<IntegriteeSignedExtra>;

pub type IntegriteeUncheckedExtrinsic<Call> =
	UncheckedExtrinsicV4<Address, Call, PairSignature, IntegriteeSignedExtra>;

/// Signature type of the [UncheckedExtrinsicV4].
pub type Signature<SignedExtra> = Option<(Address, PairSignature, SignedExtra)>;

pub type Block = generic::Block<Header, IntegriteeUncheckedExtrinsic<([u8; 2])>>;

#[cfg(feature = "std")]
pub use api::*;

#[cfg(feature = "std")]
mod api {
	use crate::ParentchainRuntimeConfig;
	use itp_api_client_types::PlainTip;
	use itp_types::parentchain::Balance;
	pub use substrate_api_client::{
		api::Error as ApiClientError,
		rpc::{tungstenite_client::TungsteniteRpcClient, Error as RpcClientError},
		Api,
	};

	pub type IntegriteeApi = Api<ParentchainRuntimeConfig<PlainTip<Balance>>, TungsteniteRpcClient>;
}
