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
use itp_types::parentchain::{IdentifyParentchain, ParentchainId};
use log::*;
use sp_runtime::traits::{Block, Header};
use std::{
	boxed::Box,
	fs,
	path::{Path, PathBuf},
	sgxfs::SgxFile,
	sync::Arc,
};

#[cfg(feature = "sgx")]
use std::sync::SgxRwLock as RwLock;

#[cfg(feature = "std")]
use std::sync::RwLock;

pub const DB_FILE: &str = "db.bin";
pub const BACKUP_FILE: &str = "db.bin.backup";

#[derive(Clone, Debug)]
pub struct LightClientStateSeal<B, LightClientState> {
	base_path: PathBuf,
	db_path: PathBuf,
	backup_path: PathBuf,
	_phantom: PhantomData<(B, LightClientState)>,
}

impl<B, L> LightClientStateSeal<B, L> {
	pub fn new(base_path: PathBuf) -> Result<Self> {
		std::fs::create_dir_all(&base_path)?;
		Ok(Self {
			base_path: base_path.clone(),
			db_path: base_path.clone().join(DB_FILE),
			backup_path: base_path.join(BACKUP_FILE),
			_phantom: Default::default(),
		})
	}

	pub fn base_path(&self) -> &Path {
		&self.base_path
	}

	pub fn db_path(&self) -> &Path {
		&self.db_path
	}

	pub fn backup_path(&self) -> &Path {
		&self.backup_path
	}

	pub fn backup(&self) -> Result<()> {
		if self.db_path().exists() {
			let _bytes = fs::copy(self.db_path(), self.backup_path())?;
		} else {
			info!("{} does not exist yet, skipping backup...", self.db_path().display())
		}
		Ok(())
	}
}

impl<B: Block, LightClientState: Decode + Encode + Debug> LightClientSealing
	for LightClientStateSeal<B, LightClientState>
{
	type LightClientState = LightClientState;

	fn seal(&self, unsealed: &LightClientState) -> Result<()> {
		trace!("Backup light client state");

		if let Err(e) = self.backup() {
			warn!("Could not backup previous light client state: Error: {}", e);
		};

		trace!("Seal light client State. Current state: {:?}", unsealed);
		Ok(unsealed.using_encoded(|bytes| seal(bytes, self.db_path()))?)
	}

	fn unseal(&self) -> Result<LightClientState> {
		Ok(unseal(self.db_path()).map(|b| Decode::decode(&mut b.as_slice()))??)
	}

	fn exists(&self) -> bool {
		SgxFile::open(self.db_path()).is_ok()
	}

	fn path(&self) -> &Path {
		self.db_path()
	}
}

/// Same as [LightClientStateSeal], but it ensures that no concurrent write operations are done
/// accross different threads.
#[derive(Debug)]
pub struct LightClientStateSealSync<B, LightClientState> {
	seal: LightClientStateSeal<B, LightClientState>,
	parentchain_id: ParentchainId,
	_rw_lock: RwLock<()>,
}

impl<B, LightClientState> LightClientStateSealSync<B, LightClientState> {
	pub fn new(base_path: PathBuf, parentchain_id: ParentchainId) -> Result<Self> {
		Ok(Self {
			seal: LightClientStateSeal::new(base_path)?,
			parentchain_id,
			_rw_lock: RwLock::new(()),
		})
	}
}

impl<B, LightClientState> IdentifyParentchain for LightClientStateSealSync<B, LightClientState> {
	fn parentchain_id(&self) -> ParentchainId {
		self.parentchain_id
	}
}

impl<B: Block, LightClientState: Decode + Encode + Debug> LightClientSealing
	for LightClientStateSealSync<B, LightClientState>
{
	type LightClientState = LightClientState;

	fn seal(&self, unsealed: &LightClientState) -> Result<()> {
		let _lock = self._rw_lock.write().map_err(|_| Error::PoisonedLock)?;
		self.seal.seal(unsealed)
	}

	fn unseal(&self) -> Result<LightClientState> {
		let _lock = self._rw_lock.read().map_err(|_| Error::PoisonedLock)?;
		self.seal.unseal()
	}

	fn exists(&self) -> bool {
		self.seal.exists()
	}

	fn path(&self) -> &Path {
		self.seal.path()
	}
}

// FIXME: This is a lot of duplicate code for the initialization of two
// different but sameish light clients. Should be tackled with #1081
pub fn read_or_init_grandpa_validator<B, OCallApi, LightClientSeal>(
	params: GrandpaParams<B::Header>,
	ocall_api: Arc<OCallApi>,
	seal: &LightClientSeal,
	parentchain_id: ParentchainId,
) -> Result<LightValidation<B, OCallApi>>
where
	B: Block,
	NumberFor<B>: finality_grandpa::BlockNumberOps,
	OCallApi: EnclaveOnChainOCallApi,
	LightClientSeal: LightClientSealing<LightClientState = LightValidationState<B>>,
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
			parentchain_id,
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

	let validator = init_grandpa_validator::<B, OCallApi>(ocall_api, init_state, parentchain_id)?;

	info!("light client state: {:?}", validator);

	seal.seal(validator.get_state())?;
	Ok(validator)
}

pub fn read_or_init_parachain_validator<B, OCallApi, LightClientSeal>(
	params: SimpleParams<B::Header>,
	ocall_api: Arc<OCallApi>,
	seal: &LightClientSeal,
	parentchain_id: ParentchainId,
) -> Result<LightValidation<B, OCallApi>>
where
	B: Block,
	NumberFor<B>: finality_grandpa::BlockNumberOps,
	OCallApi: EnclaveOnChainOCallApi,
	LightClientSeal: LightClientSealing<LightClientState = LightValidationState<B>>,
{
	if !seal.exists() {
		info!("[Enclave] ChainRelay DB not found, creating new! {}", seal.path().display());
		let validator = init_parachain_validator::<B, OCallApi>(
			ocall_api,
			RelayState::new(params.genesis_header, Default::default()).into(),
			parentchain_id,
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

	let validator = init_parachain_validator::<B, OCallApi>(ocall_api, init_state, parentchain_id)?;
	info!("light client state: {:?}", validator);

	seal.seal(validator.get_state())?;
	Ok(validator)
}

fn init_grandpa_validator<B, OCallApi>(
	ocall_api: Arc<OCallApi>,
	state: LightValidationState<B>,
	parentchain_id: ParentchainId,
) -> Result<LightValidation<B, OCallApi>>
where
	B: Block,
	NumberFor<B>: finality_grandpa::BlockNumberOps,
	OCallApi: EnclaveOnChainOCallApi,
{
	let finality: Arc<Box<dyn Finality<B> + Sync + Send + 'static>> =
		Arc::new(Box::new(GrandpaFinality));

	let validator = LightValidation::<B, OCallApi>::new(ocall_api, finality, state, parentchain_id);

	Ok(validator)
}

fn init_parachain_validator<B, OCallApi>(
	ocall_api: Arc<OCallApi>,
	state: LightValidationState<B>,
	parentchain_id: ParentchainId,
) -> Result<LightValidation<B, OCallApi>>
where
	B: Block,
	NumberFor<B>: finality_grandpa::BlockNumberOps,
	OCallApi: EnclaveOnChainOCallApi,
{
	let finality: Arc<Box<dyn Finality<B> + Sync + Send + 'static>> =
		Arc::new(Box::new(ParachainFinality));

	let validator = LightValidation::<B, OCallApi>::new(ocall_api, finality, state, parentchain_id);
	Ok(validator)
}

#[cfg(feature = "test")]
pub mod sgx_tests {
	use super::{read_or_init_parachain_validator, Arc, LightClientStateSeal, RelayState};
	use crate::{
		light_client_init_params::SimpleParams, LightClientSealing, LightClientState,
		LightValidationState,
	};
	use itc_parentchain_test::{Block, Header, ParentchainHeaderBuilder};
	use itp_sgx_temp_dir::TempDir;
	use itp_test::mock::onchain_mock::OnchainMock;
	use itp_types::parentchain::ParentchainId;
	use sp_runtime::OpaqueExtrinsic;

	type TestBlock = Block<Header, OpaqueExtrinsic>;
	type TestSeal = LightClientStateSeal<TestBlock, LightValidationState<TestBlock>>;

	fn default_simple_params() -> SimpleParams<Header> {
		SimpleParams { genesis_header: ParentchainHeaderBuilder::default().build() }
	}

	pub fn init_parachain_light_client_works() {
		let parachain_params = default_simple_params();
		let temp_dir = TempDir::with_prefix("init_parachain_light_client_works").unwrap();
		let seal = TestSeal::new(temp_dir.path().to_path_buf()).unwrap();

		let validator = read_or_init_parachain_validator::<TestBlock, OnchainMock, _>(
			parachain_params.clone(),
			Arc::new(OnchainMock::default()),
			&seal,
			ParentchainId::Integritee,
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

	pub fn sealing_creates_backup() {
		let params = default_simple_params();
		let temp_dir = TempDir::with_prefix("sealing_creates_backup").unwrap();
		let seal = TestSeal::new(temp_dir.path().to_path_buf()).unwrap();
		let state = RelayState::new(params.genesis_header, Default::default()).into();

		seal.seal(&state).unwrap();
		let unsealed = seal.unseal().unwrap();

		assert_eq!(state, unsealed);

		// The first seal operation doesn't create a backup, as there is nothing to backup.
		seal.seal(&unsealed).unwrap();
		assert!(seal.backup_path().exists())
	}

	// Todo #1293: add a unit test for the grandpa validator, but this needs a little effort for
	// setting up correct finality params.
}
