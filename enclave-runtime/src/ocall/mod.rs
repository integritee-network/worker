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

use itp_teerex_storage::{TeeRexStorageAccess, TeeRexStorageKeys};
use std::sync::Arc;

mod attestation_ocall;
mod ffi;
mod ipfs_ocall;
mod metrics_ocall;
mod on_chain_ocall;
mod sidechain_ocall;

#[derive(Clone, Debug)]
pub struct OcallApi<TeerexStorage> {
	teerex_storage: Arc<TeerexStorage>,
}

impl<TeerexStorage> OcallApi<TeerexStorage> {
	pub fn new(teerex_storage: Arc<TeerexStorage>) -> Self {
		Self { teerex_storage }
	}
}

impl<TeerexStorage> TeeRexStorageAccess for OcallApi<TeerexStorage>
where
	TeerexStorage: TeeRexStorageKeys,
{
	type TeerexStorageType = TeerexStorage;

	fn teerex_storage(&self) -> &Self::TeerexStorageType {
		self.teerex_storage.as_ref()
	}
}
