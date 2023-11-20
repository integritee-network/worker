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

use codec::{Decode, Encode};
use core::marker::PhantomData;
use frame_support::{
	pallet_prelude::TypeInfo,
	traits::{CrateVersion, PalletInfo},
	weights::constants::RocksDbWeight,
	RuntimeDebug,
};
use ita_sgx_runtime::{BlockHashCount, RuntimeCall, RuntimeEvent, RuntimeOrigin, Version};
use itp_node_api::api_client::{
	traits::ExtrinsicParamsAdjustments, Address, AssetTip, CallIndex, ExtrinsicParams,
	GenericExtrinsicParams, PairSignature, Signature, UncheckedExtrinsicV4,
};
use sp_runtime::{
	generic::Era,
	traits::{AccountIdLookup, BlakeTwo256},
};

use itp_types::parentchain::{AccountId, Balance, BlockNumber, Hash, Header, Index};

// re-export integritee network types
pub use itp_node_api::api_client::Signature as ParentchainSignature;

// define custom properties for Asset Hub
pub type ParentchainTip = AssetTip<Balance>;

#[derive(Decode, Encode, Clone, Eq, PartialEq, Debug)]
pub struct ParentchainExtrinsicParams {
	era: Era,
	nonce: Index,
	tip: ParentchainTip,
	spec_version: u32,
	transaction_version: u32,
	genesis_hash: Hash,
	mortality_checkpoint: Hash,
}

#[derive(Decode, Encode, Copy, Clone, Eq, PartialEq, Debug)]
pub struct ParentchainAdditionalParams {
	era: Era,
	mortality_checkpoint: Option<Hash>,
	tip: ParentchainTip,
}
impl Default for ParentchainAdditionalParams {
	fn default() -> Self {
		Self { era: Era::Immortal, mortality_checkpoint: None, tip: ParentchainTip::default() }
	}
}

#[derive(Decode, Encode, Copy, Clone, Eq, PartialEq, Debug)]
pub struct ParentchainSignedExtra {
	pub era: Era,
	#[codec(compact)]
	pub nonce: Index,
	pub tip: ParentchainTip,
}

pub type ParentchainAdditionalSigned = ((), u32, u32, Hash, Hash, (), (), ());

impl ExtrinsicParams<Index, Hash> for ParentchainExtrinsicParams {
	type AdditionalParams = ParentchainAdditionalParams;
	type SignedExtra = ParentchainSignedExtra;
	type AdditionalSigned = ParentchainAdditionalSigned;

	fn new(
		spec_version: u32,
		transaction_version: u32,
		nonce: Index,
		genesis_hash: Hash,
		additional_params: Self::AdditionalParams,
	) -> Self {
		Self {
			era: additional_params.era,
			tip: additional_params.tip,
			spec_version,
			transaction_version,
			genesis_hash,
			mortality_checkpoint: additional_params.mortality_checkpoint.unwrap_or(genesis_hash),
			nonce,
		}
	}

	fn signed_extra(&self) -> Self::SignedExtra {
		Self::SignedExtra { era: self.era, nonce: self.nonce, tip: self.tip }
	}

	fn additional_signed(&self) -> Self::AdditionalSigned {
		(
			(),
			self.spec_version,
			self.transaction_version,
			self.genesis_hash,
			self.mortality_checkpoint,
			(),
			(),
			(),
		)
	}
}

impl ExtrinsicParamsAdjustments<ParentchainAdditionalParams> for ParentchainExtrinsicParams {
	fn with_nonce(&self, nonce: Index) -> Self {
		Self {
			era: self.era,
			tip: self.tip,
			spec_version: self.spec_version,
			transaction_version: self.transaction_version,
			genesis_hash: self.genesis_hash,
			mortality_checkpoint: self.mortality_checkpoint,
			nonce,
		}
	}
	fn with_additional_params(&self, additional_params: ParentchainAdditionalParams) -> Self {
		Self {
			era: additional_params.era,
			tip: additional_params.tip,
			spec_version: self.spec_version,
			transaction_version: self.transaction_version,
			genesis_hash: self.genesis_hash,
			mortality_checkpoint: additional_params
				.mortality_checkpoint
				.unwrap_or(self.genesis_hash),
			nonce: self.nonce,
		}
	}
	fn with_spec_version(&self, spec_version: u32) -> Self {
		Self {
			era: self.era,
			tip: self.tip,
			spec_version,
			transaction_version: self.transaction_version,
			genesis_hash: self.genesis_hash,
			mortality_checkpoint: self.mortality_checkpoint,
			nonce: self.nonce,
		}
	}
	fn with_transaction_version(&self, transaction_version: u32) -> Self {
		Self {
			era: self.era,
			tip: self.tip,
			spec_version: self.spec_version,
			transaction_version,
			genesis_hash: self.genesis_hash,
			mortality_checkpoint: self.mortality_checkpoint,
			nonce: self.nonce,
		}
	}
}
pub struct ExtrinsicParser<SignedExtra> {
	_phantom: PhantomData<SignedExtra>,
}

/// Parses the extrinsics corresponding to the parentchain.
pub type ParentchainExtrinsicParser = ExtrinsicParser<ParentchainSignedExtra>;

/// Partially interpreted extrinsic containing the `signature` and the `call_index` whereas
/// the `call_args` remain in encoded form.
///
/// Intended for usage, where the actual `call_args` form is unknown.
pub struct SemiOpaqueExtrinsic<'a, SignedExtra> {
	/// Signature of the Extrinsic.
	pub signature: Signature<SignedExtra>,
	/// Call index of the dispatchable.
	pub call_index: CallIndex,
	/// Encoded arguments of the dispatchable corresponding to the `call_index`.
	pub call_args: &'a [u8],
}

/// Trait to extract signature and call indexes of an encoded [UncheckedExtrinsicV4].
pub trait ParseExtrinsic {
	/// Signed extra of the extrinsic.
	type SignedExtra;

	fn parse(encoded_call: &[u8]) -> Result<SemiOpaqueExtrinsic<Self::SignedExtra>, codec::Error>;
}

impl<SignedExtra> ParseExtrinsic for ExtrinsicParser<SignedExtra>
where
	SignedExtra: Decode + Encode,
{
	type SignedExtra = SignedExtra;

	/// Extract a call index of an encoded call.
	fn parse(encoded_call: &[u8]) -> Result<SemiOpaqueExtrinsic<Self::SignedExtra>, codec::Error> {
		let call_mut = &mut &encoded_call[..];

		// `()` is a trick to stop decoding after the call index. So the remaining bytes
		//  of `call` after decoding only contain the parentchain's dispatchable's arguments.
		let xt = UncheckedExtrinsicV4::<
            Address,
            (CallIndex, ()),
            PairSignature,
            Self::SignedExtra,
        >::decode(call_mut)?;

		Ok(SemiOpaqueExtrinsic {
			signature: xt.signature,
			call_index: xt.function.0,
			call_args: call_mut,
		})
	}
}
