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
	error::Result,
	finality::{Finality, GrandpaFinality, ParachainFinality},
	light_client_init_params::{GrandpaParams, SimpleParams},
	light_validation::{check_validator_set_proof, LightValidation},
	state::RelayState,
	LightClientSealing, LightClientState, LightValidationState, NumberFor, Validator,
};
use codec::{Decode, Encode};
use core::{fmt::Debug, marker::PhantomData};
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_sgx_io::{seal, unseal};
use log::*;
use sp_runtime::traits::{Block, Header};
use std::{
	boxed::Box,
	fs,
	path::{Path, PathBuf},
	sgxfs::SgxFile,
	sync::Arc,
};

#[derive(Clone, Debug)]
pub struct LightClientStateSeal<B, LightClientState> {
	path_buf: PathBuf,
	_phantom: PhantomData<(B, LightClientState)>,
}

impl<B, L> LightClientStateSeal<B, L> {
	pub fn new(path: &str) -> Self {
		Self { path_buf: PathBuf::from(path), _phantom: Default::default() }
	}
}

impl<B: Block, LightClientState: Decode + Encode + Debug> LightClientSealing<LightClientState>
	for LightClientStateSeal<B, LightClientState>
{
	fn seal(&self, unsealed: &LightClientState) -> Result<()> {
		debug!("backup light client state");
		if fs::copy(&self.path(), &self.path().join(".1")).is_err() {
			warn!("could not backup previous light client state");
		};
		debug!("Seal light client State. Current state: {:?}", unsealed);
		Ok(unsealed.using_encoded(|bytes| seal(bytes, self.path()))?)
	}

	fn unseal(&self) -> Result<LightClientState> {
		Ok(unseal(self.path()).map(|b| Decode::decode(&mut b.as_slice()))??)
	}

	fn exists(&self) -> bool {
		SgxFile::open(self.path()).is_ok()
	}

	fn path(&self) -> &Path {
		&self.path_buf.as_path()
	}
}

// FIXME: This is a lot of duplicate code for the initialization of two
// different but sameish light clients. Should be tackled with #1081
pub fn read_or_init_grandpa_validator<B, OCallApi, LightClientSeal>(
	params: GrandpaParams<B::Header>,
	ocall_api: Arc<OCallApi>,
	seal: &LightClientSeal,
) -> Result<LightValidation<B, OCallApi>>
where
	B: Block,
	NumberFor<B>: finality_grandpa::BlockNumberOps,
	OCallApi: EnclaveOnChainOCallApi,
	LightClientSeal: LightClientSealing<LightValidationState<B>>,
{
	check_validator_set_proof::<B>(
		params.genesis_header.state_root(),
		params.authority_proof,
		&params.authorities,
	)?;

	if !seal.exists() {
		info!("[Enclave] ChainRelay DB not found, creating new! {}", seal.path().display());
		let validator = init_grandpa_validator::<B, OCallApi>(
			ocall_api,
			RelayState::new(params.genesis_header, params.authorities).into(),
		)?;
		seal.seal(validator.get_state())?;
		return Ok(validator)
	}

	let validation_state = seal.unseal()?;
	let genesis_hash = validation_state.genesis_hash()?;

	let init_state = if genesis_hash == params.genesis_header.hash() {
		info!("Found already initialized light client with Genesis Hash: {:?}", genesis_hash);
		validation_state
	} else {
		info!(
			"Previous light client db belongs to another parentchain genesis. Creating new: {:?}",
			genesis_hash
		);
		RelayState::new(params.genesis_header, params.authorities).into()
	};

	let validator = init_grandpa_validator::<B, OCallApi>(ocall_api, init_state)?;

	info!("light client state: {:?}", validator);

	seal.seal(validator.get_state())?;
	Ok(validator)
}

pub fn read_or_init_parachain_validator<B, OCallApi, LightClientSeal>(
	params: SimpleParams<B::Header>,
	ocall_api: Arc<OCallApi>,
	seal: &LightClientSeal,
) -> Result<LightValidation<B, OCallApi>>
where
	B: Block,
	NumberFor<B>: finality_grandpa::BlockNumberOps,
	OCallApi: EnclaveOnChainOCallApi,
	LightClientSeal: LightClientSealing<LightValidationState<B>>,
{
	if !seal.exists() {
		info!("[Enclave] ChainRelay DB not found, creating new! {}", seal.path().display());
		let validator = init_parachain_validator::<B, OCallApi>(
			ocall_api,
			RelayState::new(params.genesis_header, Default::default()).into(),
		)?;
		seal.seal(validator.get_state())?;
		return Ok(validator)
	}

	let validation_state = seal.unseal()?;
	let genesis_hash = validation_state.genesis_hash()?;

	let init_state = if genesis_hash == params.genesis_header.hash() {
		info!("Found already initialized light client with Genesis Hash: {:?}", genesis_hash);
		validation_state
	} else {
		info!(
			"Previous light client db belongs to another parentchain genesis. Creating new: {:?}",
			genesis_hash
		);
		RelayState::new(params.genesis_header, vec![]).into()
	};

	let validator = init_parachain_validator::<B, OCallApi>(ocall_api, init_state)?;
	info!("light client state: {:?}", validator);

	seal.seal(validator.get_state())?;
	Ok(validator)
}

fn init_grandpa_validator<B, OCallApi>(
	ocall_api: Arc<OCallApi>,
	state: LightValidationState<B>,
) -> Result<LightValidation<B, OCallApi>>
where
	B: Block,
	NumberFor<B>: finality_grandpa::BlockNumberOps,
	OCallApi: EnclaveOnChainOCallApi,
{
	let finality: Arc<Box<dyn Finality<B> + Sync + Send + 'static>> =
		Arc::new(Box::new(GrandpaFinality));

	let validator = LightValidation::<B, OCallApi>::new(ocall_api, finality, state);

	Ok(validator)
}

fn init_parachain_validator<B, OCallApi>(
	ocall_api: Arc<OCallApi>,
	state: LightValidationState<B>,
) -> Result<LightValidation<B, OCallApi>>
where
	B: Block,
	NumberFor<B>: finality_grandpa::BlockNumberOps,
	OCallApi: EnclaveOnChainOCallApi,
{
	let finality: Arc<Box<dyn Finality<B> + Sync + Send + 'static>> =
		Arc::new(Box::new(ParachainFinality));

	let validator = LightValidation::<B, OCallApi>::new(ocall_api, finality, state);
	Ok(validator)
}

#[cfg(feature = "test")]
pub mod sgx_tests {
	use super::{read_or_init_parachain_validator, Arc, LightClientStateSeal};
	use crate::{light_client_init_params::SimpleParams, LightClientState, LightValidationState};
	use itc_parentchain_test::{Block, Header, ParentchainHeaderBuilder};
	use itp_sgx_temp_dir::TempDir;
	use itp_test::mock::onchain_mock::OnchainMock;
	use sp_runtime::OpaqueExtrinsic;

	type TestBlock = Block<Header, OpaqueExtrinsic>;
	type TestSeal = LightClientStateSeal<TestBlock, LightValidationState<TestBlock>>;

	fn default_simple_params() -> SimpleParams<Header> {
		SimpleParams { genesis_header: ParentchainHeaderBuilder::default().build() }
	}

	pub fn init_parachain_light_client_works() {
		let parachain_params = default_simple_params();
		let temp_dir = TempDir::with_prefix("init_parachain_light_client_works").unwrap();
		let seal = TestSeal::new(temp_dir.path().to_str().unwrap());

		let validator = read_or_init_parachain_validator::<TestBlock, OnchainMock, _>(
			parachain_params.clone(),
			Arc::new(OnchainMock::default()),
			&seal,
		)
		.unwrap();

		assert_eq!(validator.genesis_hash().unwrap(), parachain_params.genesis_header.hash());
		assert_eq!(validator.num_xt_to_be_included().unwrap(), 0);
		assert_eq!(validator.latest_finalized_header().unwrap(), parachain_params.genesis_header);
		assert_eq!(
			validator.penultimate_finalized_block_header().unwrap(),
			parachain_params.genesis_header
		);
	}

	// Todo #1293: add a unit test for the grandpa validator, but this needs a little effort for
	// setting up correct finality params.
}
