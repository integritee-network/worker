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
use itp_api_client_types::Preamble;
use itp_node_api::api_client::{Address, CallIndex, PairSignature, UncheckedExtrinsic};

pub struct ExtrinsicParser<SignedExtra> {
	_phantom: PhantomData<SignedExtra>,
}

/// Partially interpreted extrinsic containing the `preamble` and the `call_index` whereas
/// the `call_args` remain in encoded form.
///
/// Intended for usage, where the actual `call_args` form is unknown.
pub struct SemiOpaqueExtrinsic<'a, TxExtension> {
	/// Signature of the Extrinsic.
	pub preamble: Preamble<TxExtension>,
	/// Call index of the dispatchable.
	pub call_index: CallIndex,
	/// Encoded arguments of the dispatchable corresponding to the `call_index`.
	pub call_args: &'a [u8],
}

/// Trait to extract signature and call indexes of an encoded [UncheckedExtrinsic].
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
		let xt = UncheckedExtrinsic::<
            Address,
            (CallIndex, ()),
            PairSignature,
            Self::SignedExtra,
        >::decode(call_mut)?;

		Ok(SemiOpaqueExtrinsic {
			preamble: xt.preamble,
			call_index: xt.function.0,
			call_args: call_mut,
		})
	}
}
