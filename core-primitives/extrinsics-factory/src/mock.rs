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

use crate::{error::Result, CreateExtrinsics};
use itp_types::OpaqueCall;
use sp_runtime::OpaqueExtrinsic;
use std::vec::Vec;

/// Mock of an extrinsics factory. To be used in unit tests.
///
/// Returns an empty extrinsic.
#[derive(Default, Clone)]
pub struct ExtrinsicsFactoryMock;

impl CreateExtrinsics for ExtrinsicsFactoryMock {
	fn create_extrinsics(&self, _calls: &[OpaqueCall]) -> Result<Vec<OpaqueExtrinsic>> {
		// Ok(calls
		// 	.iter()
		// 	.map(|_| OpaqueExtrinsic::from_bytes(Vec::new().as_slice()).unwrap())
		// 	.collect())
		Ok(Vec::new())
	}
}
