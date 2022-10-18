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
use codec::{Decode, Error, Input};
use std::slice;

/// Helper trait to transform the sgx-ffi pointers to any type that implements
/// `parity-scale-codec::Decode`
pub unsafe trait DecodeRaw {
	/// the type to decode into
	type Decoded: Decode;

	unsafe fn decode_raw<'a, T>(data: *const T, len: usize) -> Result<Self::Decoded, codec::Error>
	where
		T: 'a,
		&'a [T]: Input;
}

unsafe impl<D: Decode> DecodeRaw for D {
	type Decoded = D;

	unsafe fn decode_raw<'a, T>(data: *const T, len: usize) -> Result<Self::Decoded, Error>
	where
		T: 'a,
		&'a [T]: Input,
	{
		let mut s = slice::from_raw_parts(data, len);

		Decode::decode(&mut s)
	}
}

pub unsafe fn utf8_str_from_raw<'a>(
	data: *const u8,
	len: usize,
) -> Result<&'a str, std::str::Utf8Error> {
	let bytes = slice::from_raw_parts(data, len);

	std::str::from_utf8(bytes)
}

pub(crate) fn get_triggered_dispatcher_from_solo_or_parachain(
) -> Result<EnclaveTriggeredParentchainBlockImportDispatcher> {
	if let Ok(solochain_handler) = GLOBAL_FULL_SOLOCHAIN_HANDLER_COMPONENT.get() {
		get_triggered_dispatcher(solochain_handler.import_dispatcher)
	} else if let Ok(parachain_handler) = GLOBAL_FULL_PARACHAIN_HANDLER_COMPONENT.get() {
		get_triggered_dispatcher(parachain_handler.import_dispatcher)
	} else {
		return Err(Error::NoParentchainAssigned)
	};
}

pub(crate) fn get_triggered_dispatcher(
	dispatcher: Option<Arc<EnclaveParentchainBlockImportDispatcher>>,
) -> Result<EnclaveTriggeredParentchainBlockImportDispatcher> {
	let triggered_dispatcher = dispatcher
		.ok_or(Error::ExpectedTriggeredImportDispatcher)?
		.triggered_dispatcher()
		.ok_or(Error::ExpectedTriggeredImportDispatcher)?;
	Ok(triggered_dispatcher)
}

pub(crate) fn get_validator_accessor_from_solo_or_parachain(
) -> Result<Arc<EnclaveValidatorAccessor>> {
	if let Ok(solochain_handler) = GLOBAL_FULL_SOLOCHAIN_HANDLER_COMPONENT.get() {
		solochain_handler.validator_accessor
	} else if let Ok(parachain_handler) = GLOBAL_FULL_PARACHAIN_HANDLER_COMPONENT.get() {
		parachain_handler.validator_accessor
	} else {
		return Err(Error::NoParentchainAssigned)
	};
}
