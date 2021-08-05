/*
	Copyright 2019 Supercomputing Systems AG

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

use crate::ocall::{
	attestation_ocall::EnclaveAttestationOCall, ipfs_ocall::EnclaveIpfsOcall,
	on_chain_ocall::EnclaveOnChainOCall, rpc_ocall::EnclaveRpcOCall,
};
use std::sync::Arc;
use substratee_ocall_api::{
	EnclaveAttestationOCallApi, EnclaveIpfsOCallApi, EnclaveOnChainOCallApi, EnclaveRpcOCallApi,
};

/// Abstract factory trait for OCall components
pub trait OCallComponentFactoryTrait<A, R, O, I>
where
	A: EnclaveAttestationOCallApi,
	R: EnclaveRpcOCallApi,
	O: EnclaveOnChainOCallApi,
	I: EnclaveIpfsOCallApi,
{
	fn attestation_api() -> Arc<A>;

	fn rpc_api() -> Arc<R>;

	fn on_chain_api() -> Arc<O>;

	fn ipfs_api() -> Arc<I>;
}

/// Concrete implementation of the factory, producing components for live system (i.e. not mocks)
pub struct OCallComponentFactory {}

impl
	OCallComponentFactoryTrait<
		EnclaveAttestationOCall,
		EnclaveRpcOCall,
		EnclaveOnChainOCall,
		EnclaveIpfsOcall,
	> for OCallComponentFactory
{
	fn attestation_api() -> Arc<EnclaveAttestationOCall> {
		Arc::new(EnclaveAttestationOCall {})
	}

	fn rpc_api() -> Arc<EnclaveRpcOCall> {
		Arc::new(EnclaveRpcOCall {})
	}

	fn on_chain_api() -> Arc<EnclaveOnChainOCall> {
		Arc::new(EnclaveOnChainOCall {})
	}

	fn ipfs_api() -> Arc<EnclaveIpfsOcall> {
		Arc::new(EnclaveIpfsOcall {})
	}
}
