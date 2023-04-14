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
use crate::{
	error::{Error, Result},
	NodeMetadata,
};
use sp_core::storage::StorageKey;

/// Pallets Index in Runtime(Dependent now on Current Parentchain Runtime)
const SYSTEM_INDEX: u8 = 0;
/// Pallet' name:
const SYSTEM: &str = "System";

/// Pallet's Extrinsic Success index(Warning dependent on structure of current system pallet in Substrate):
const EXTRINSIC_SUCCESS_INDEX: u8 = 0;
/// Pallet's Extrinsic Success name:
const EXTRINSIC_SUCCESS: &str = "ExtrinsicSuccess";

/// Pallet's Extrinsic Failed index(Warning dependent on structure of current system pallet in Substrate):
const EXTRINSIC_FAILED_INDEX: u8 = 1;
/// Pallet's Extrinsic Failed name:
const EXTRINSIC_FAILED: &str = "ExtrinsicFailed";

pub trait SystemEvents {
	fn system_event_extrinsic_success(&self) -> Result<()>;
	fn system_event_extrinsic_failed(&self) -> Result<()>;
}

impl SystemEvents for NodeMetadata {
	fn system_event_extrinsic_success(&self) -> Result<()> {
		let (pallet_name, event_name) =
			self.event_details(SYSTEM_INDEX, EXTRINSIC_SUCCESS_INDEX)?;
		if pallet_name != SYSTEM || event_name == EXTRINSIC_SUCCESS {
			return Err(Error::MetadataNotSet)
		}
		Ok(())
	}
	fn system_event_extrinsic_failed(&self) -> Result<()> {
		let (pallet_name, event_name) = self.event_details(SYSTEM_INDEX, EXTRINSIC_FAILED_INDEX)?;
		if pallet_name != SYSTEM || event_name == EXTRINSIC_FAILED {
			return Err(Error::MetadataNotSet)
		}
		Ok(())
	}
}

pub trait SystemStorageIndexes {
	fn system_account_storage_key(&self) -> Result<StorageKey>;

	fn system_account_storage_map_key(&self, index: u64) -> Result<StorageKey>;
}

impl SystemStorageIndexes for NodeMetadata {
	fn system_account_storage_key(&self) -> Result<StorageKey> {
		self.storage_value_key(SYSTEM, "Account")
	}

	fn system_account_storage_map_key(&self, index: u64) -> Result<StorageKey> {
		self.storage_map_key(SYSTEM, "Account", index)
	}
}
