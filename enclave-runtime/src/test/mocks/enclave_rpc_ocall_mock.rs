/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
	Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.

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

use crate::rpc::author::alloc::prelude::v1::Vec;
use codec::Encode;
use itp_types::TrustedOperationStatus;
use itp_ocall_api::EnclaveRpcOCallApi;
use sgx_types::SgxResult;

#[derive(Clone, Debug, Default)]
pub struct EnclaveRpcOCallMock;

impl EnclaveRpcOCallApi for EnclaveRpcOCallMock {
	fn update_status_event<H: Encode>(
		&self,
		_hash: H,
		_status_update: TrustedOperationStatus,
	) -> SgxResult<()> {
		Ok(())
	}

	fn send_state<H: Encode>(&self, _hash: H, _value_opt: Option<Vec<u8>>) -> SgxResult<()> {
		Ok(())
	}
}
