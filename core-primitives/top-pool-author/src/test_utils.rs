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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use crate::traits::AuthorApi;
use codec::Encode;
use ita_stf::{ShardIdentifier, TrustedCallSigned, TrustedGetterSigned, TrustedOperation};
use itp_sgx_crypto::ShieldingCrypto;
use jsonrpc_core::futures::executor;
use sp_core::H256;
use std::{fmt::Debug, vec::Vec};

/// Test utility function to submit a trusted operation on an RPC author
pub fn submit_operation_to_top_pool<R, S>(
	author: &R,
	top: &TrustedOperation,
	shielding_key: &S,
	shard: ShardIdentifier,
) -> Result<H256, jsonrpc_core::Error>
where
	R: AuthorApi<H256, H256>,
	S: ShieldingCrypto,
	S::Error: Debug,
{
	let top_encrypted = shielding_key.encrypt(top.encode().as_slice()).unwrap();
	let submit_future = async { author.submit_top(top_encrypted, shard).await };
	executor::block_on(submit_future)
}

/// Get all pending trusted operations, grouped into calls and getters
pub fn get_pending_tops_separated<R>(
	top_pool_author: &R,
	shard: ShardIdentifier,
) -> (Vec<TrustedCallSigned>, Vec<TrustedGetterSigned>)
where
	R: AuthorApi<H256, H256>,
{
	top_pool_author.get_pending_tops_separated(shard).unwrap()
}
