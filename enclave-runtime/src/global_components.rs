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

use crate::ocall::OcallApi;
use itc_parentchain::{
	block_import_dispatcher::immediate_dispatcher::ImmediateDispatcher,
	block_importer::ParentchainBlockImporter, indirect_calls_executor::IndirectCallsExecutor,
	light_client::ValidatorAccessor,
};
use itp_component_container::ComponentContainer;
use itp_extrinsics_factory::ExtrinsicsFactory;
use itp_nonce_cache::NonceCache;
use itp_stf_executor::executor::StfExecutor;
use itp_stf_state_handler::GlobalFileStateHandler;
use itp_types::Block;
use sgx_crypto_helper::rsa3072::Rsa3072KeyPair;
use sgx_externalities::SgxExternalities;
use sp_core::ed25519::Pair;

/// Here we define all the concrete types that we use in the enclave.
/// Required in order to instantiate the components we use in a global context.
pub type EnclaveStfExecutor = StfExecutor<OcallApi, GlobalFileStateHandler, SgxExternalities>;
pub type EnclaveExtrinsicsFactory = ExtrinsicsFactory<Pair, NonceCache>;
pub type EnclaveIndirectCallsExecutor = IndirectCallsExecutor<Rsa3072KeyPair, EnclaveStfExecutor>;
pub type EnclaveValidatorAccessor = ValidatorAccessor<Block>;
pub type EnclaveParentChainBlockImporter = ParentchainBlockImporter<
	Block,
	EnclaveValidatorAccessor,
	OcallApi,
	EnclaveStfExecutor,
	EnclaveExtrinsicsFactory,
	EnclaveIndirectCallsExecutor,
>;
//pub type EnclaveBlockImportQueue = BlockImportQueue<Block>;
pub type EnclaveParentchainBlockImportDispatcher =
	ImmediateDispatcher<EnclaveParentChainBlockImporter>;

pub static GLOBAL_DISPATCHER_COMPONENT: ComponentContainer<
	EnclaveParentchainBlockImportDispatcher,
> = ComponentContainer::new();
