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

#[cfg(feature = "test")]
use crate::test_genesis::test_genesis_setup;
use crate::{
	helpers::{
		enclave_signer_account, get_shard_vaults, shard_creation_info, shard_vault,
		shielding_target_genesis_hash,
	},
	Stf, TrustedCall, TrustedCallSigned, ENCLAVE_ACCOUNT_KEY,
};
use codec::{Decode, Encode};
use frame_support::traits::{OnTimestampSet, OriginTrait, UnfilteredDispatchable};
use ita_parentchain_specs::MinimalChainSpec;
use ita_sgx_runtime::{
	ExistentialDeposit, ParentchainInstanceIntegritee, ParentchainInstanceTargetA,
	ParentchainInstanceTargetB,
};
use itp_node_api::metadata::{provider::AccessNodeMetadata, NodeMetadataTrait};
use itp_pallet_storage::{
	EnclaveBridgeStorage, EnclaveBridgeStorageKeys, SidechainPalletStorage,
	SidechainPalletStorageKeys,
};
use itp_sgx_externalities::SgxExternalitiesTrait;
use itp_sgx_runtime_primitives::types::Moment;
use itp_stf_interface::{
	parentchain_mirror_prefix,
	parentchain_pallet::ParentchainPalletInstancesInterface,
	sudo_pallet::SudoPalletInterface,
	system_pallet::{SystemPalletAccountInterface, SystemPalletEventInterface},
	ExecuteCall, ExecuteGetter, InitState, ShardCreationInfo, ShardCreationQuery, ShardVaultQuery,
	StateCallInterface, StateGetterInterface, UpdateState,
};
use itp_stf_primitives::{
	error::StfError,
	traits::TrustedCallVerification,
	types::{ShardIdentifier, Signature},
};
use itp_storage::storage_value_key;
use itp_types::{
	parentchain::{AccountId, BlockNumber, Hash, ParentchainCall, ParentchainId},
	Nonce,
};
use itp_utils::{hex::hex_encode, stringify::account_id_to_string};
use log::*;
use sp_runtime::{traits::StaticLookup, SaturatedConversion};
use std::{fmt::Debug, format, prelude::v1::*, sync::Arc, vec};

impl<TCS, G, State, Runtime, AccountId> InitState<State, AccountId> for Stf<TCS, G, State, Runtime>
where
	State: SgxExternalitiesTrait + Debug,
	<State as SgxExternalitiesTrait>::SgxExternalitiesType: core::default::Default,
	Runtime: frame_system::Config<AccountId = AccountId> + pallet_balances::Config,
	<<Runtime as frame_system::Config>::Lookup as StaticLookup>::Source:
		std::convert::From<AccountId>,
	AccountId: Encode,
{
	fn init_state(enclave_account: AccountId) -> State {
		debug!("initializing stf state, account id {}", account_id_to_string(&enclave_account));
		let mut state = State::new(Default::default());

		state.execute_with(|| {
			sp_io::storage::set(&storage_value_key("Balances", "TotalIssuance"), &0u128.encode());
		});

		#[cfg(feature = "test")]
		test_genesis_setup(&mut state);

		state.execute_with(|| {
			sp_io::storage::set(
				&storage_value_key("Sudo", ENCLAVE_ACCOUNT_KEY),
				&enclave_account.encode(),
			);

			if let Err(e) = create_enclave_self_account::<Runtime, AccountId>(enclave_account) {
				error!("Failed to initialize the enclave signer account: {:?}", e);
			}
		});

		trace!("Returning updated state: {:?}", state);
		state
	}
}

impl<TCS, G, State, Runtime>
	UpdateState<State, <State as SgxExternalitiesTrait>::SgxExternalitiesDiffType>
	for Stf<TCS, G, State, Runtime>
where
	State: SgxExternalitiesTrait + Debug,
	<State as SgxExternalitiesTrait>::SgxExternalitiesType: core::default::Default,
	<State as SgxExternalitiesTrait>::SgxExternalitiesDiffType:
		IntoIterator<Item = (Vec<u8>, Option<Vec<u8>>)>,
{
	fn apply_state_diff(
		state: &mut State,
		map_update: <State as SgxExternalitiesTrait>::SgxExternalitiesDiffType,
	) {
		state.execute_with(|| {
			map_update.into_iter().for_each(|(k, v)| {
				trace!(
					"apply_state_diff (mirror): key = {}, value= {:?}",
					hex_encode(&k),
					v.clone().map(|v| hex_encode(&v))
				);
				match v {
					Some(value) => sp_io::storage::set(&k, &value),
					None => sp_io::storage::clear(&k),
				};
			});
		});
	}

	fn storage_hashes_to_update_on_block(
		parentchain_id: &ParentchainId,
		shard: &ShardIdentifier,
	) -> Vec<Vec<u8>> {
		match parentchain_id {
			ParentchainId::Integritee => vec![
				EnclaveBridgeStorage::shard_status(*shard),
				EnclaveBridgeStorage::upgradable_shard_config(*shard),
				SidechainPalletStorage::latest_sidechain_block_confirmation(*shard),
			], // shards_key_hash() moved to stf_executor and is currently unused
			ParentchainId::TargetA => vec![],
			ParentchainId::TargetB => vec![],
		}
	}
}

impl<TCS, G, State, Runtime, NodeMetadataRepository>
	StateCallInterface<TCS, State, NodeMetadataRepository> for Stf<TCS, G, State, Runtime>
where
	TCS: PartialEq
		+ ExecuteCall<NodeMetadataRepository>
		+ Encode
		+ Decode
		+ Debug
		+ Clone
		+ Sync
		+ Send
		+ TrustedCallVerification,
	State: SgxExternalitiesTrait + Debug,
	NodeMetadataRepository: AccessNodeMetadata,
	NodeMetadataRepository::MetadataType: NodeMetadataTrait,
	Runtime: frame_system::Config + frame_pallet_timestamp::Config,
	<Runtime as frame_pallet_timestamp::Config>::Moment: std::convert::From<u64>,
{
	type Error = TCS::Error;

	fn execute_call(
		state: &mut State,
		shard: &ShardIdentifier,
		call: TCS,
		calls: &mut Vec<ParentchainCall>,
		node_metadata_repo: Arc<NodeMetadataRepository>,
	) -> Result<(), Self::Error> {
		state.execute_with(|| call.execute(calls, shard, node_metadata_repo))
	}

	fn on_initialize(state: &mut State, now: Moment) -> Result<(), Self::Error> {
		trace!("on_initialize called at epoch {}", now);
		state.execute_with(|| {
			// as pallet_timestamp doesn't export set_timestamp in no_std, we need to re-build the same behaviour
			sp_io::storage::set(&storage_value_key("Timestamp", "Now"), &now.encode());
			sp_io::storage::set(&storage_value_key("Timestamp", "DidUpdate"), &true.encode());
			<Runtime::OnTimestampSet as OnTimestampSet<_>>::on_timestamp_set(now.into());
		});
		Ok(())
	}

	fn maintenance_mode_tasks(
		age_blocks: i32,
		state: &mut State,
		shard: &ShardIdentifier,
		calls: &mut Vec<ParentchainCall>,
		node_metadata_repo: Arc<NodeMetadataRepository>,
	) -> Result<(), Self::Error> {
		if BlockNumber::saturated_from(age_blocks)
			> MinimalChainSpec::maintenance_mode_duration_before_retirement(
				shielding_target_genesis_hash().unwrap_or_default(),
			) {
			warn!("Maintenance mode has expired. Executing shard retirement tasks");
			// find one account with nonzero balance: assets first, then native
			state.execute_with(|| {
				// TODO: this is only for native. do it for all assets too
				// TODO: ensure this doesn't run longer than remaining block production time. We still must avoid forks
				let accounts: Vec<(AccountId, Nonce)> =
					frame_system::Account::<ita_sgx_runtime::Runtime>::iter()
						.filter_map(|(account_id, account_info)| {
							(account_info.data.free > ExistentialDeposit::get())
								.then_some((account_id, account_info.nonce))
						})
						.collect();
				info!("found {} accounts to recover", accounts.len());
				// we won't put this call through the TOP pool. No signature check will happen.
				// We just want to use the handy ExecuteCall trait
				let fake_signature =
					Signature::Sr25519([0u8; 64].as_slice().try_into().expect("must work"));
				for (account, nonce) in accounts {
					info!("force unshield for {:?}", account);
					let tcs = TrustedCallSigned {
						call: TrustedCall::force_unshield_all(
							account.clone(),
							account.clone(),
							None,
						),
						nonce,
						delegate: None,
						signature: fake_signature.clone(),
					};
					// Replace with `inspect_err` once it's stable.
					tcs.execute(calls, shard, node_metadata_repo.clone())
						.map_err(|e| {
							error!("Failed to force-unshield for {:?}: {:?}", account, e);
							()
						})
						.ok();
				}
				Ok(())
			})
		} else {
			info!(
				"Maintenance mode is active and retirement will start in {} parentchain blocks",
				MinimalChainSpec::maintenance_mode_duration_before_retirement(
					shielding_target_genesis_hash().unwrap_or_default(),
				) - BlockNumber::saturated_from(age_blocks)
			);
			Ok(())
		}
	}

	fn on_finalize(_state: &mut State) -> Result<(), Self::Error> {
		trace!("on_finalize called");

		Ok(())
	}
}

impl<TCS, G, State, Runtime> StateGetterInterface<G, State> for Stf<TCS, G, State, Runtime>
where
	G: PartialEq + ExecuteGetter,
	State: SgxExternalitiesTrait + Debug,
{
	fn execute_getter(state: &mut State, getter: G) -> Option<Vec<u8>> {
		state.execute_with(|| getter.execute())
	}

	fn get_parentchain_mirror_state<V: Decode>(
		state: &mut State,
		parentchain_key: Vec<u8>,
		parentchain_id: &ParentchainId,
	) -> Option<V> {
		let mut full_key = parentchain_mirror_prefix(parentchain_id).as_bytes().to_vec();
		full_key.extend_from_slice(&parentchain_key);
		trace!("get_parentchain_mirror_state: prefixed key = {}", hex_encode(&full_key));
		let maybe_raw_state = state.get(&full_key);
		trace!(
			"get_parentchain_mirror_state: raw_state: {:?}",
			maybe_raw_state.map(|raw| hex_encode(&raw))
		);
		if let Some(raw_state) = maybe_raw_state {
			if let Ok(state) = V::decode(&mut raw_state.as_slice()) {
				Some(state)
			} else {
				warn!("get_parentchain_mirror_state: decode failed");
				None
			}
		} else {
			None
		}
	}
}

impl<TCS, G, State, Runtime> ShardVaultQuery<State> for Stf<TCS, G, State, Runtime>
where
	State: SgxExternalitiesTrait + Debug,
{
	fn get_vault(state: &mut State) -> Option<(AccountId, ParentchainId)> {
		state.execute_with(shard_vault)
	}
}

impl<TCS, G, State, Runtime> ShardCreationQuery<State> for Stf<TCS, G, State, Runtime>
where
	State: SgxExternalitiesTrait + Debug,
{
	fn get_shard_creation_info(state: &mut State) -> ShardCreationInfo {
		state.execute_with(shard_creation_info)
	}
}

impl<TCS, G, State, Runtime> SudoPalletInterface<State> for Stf<TCS, G, State, Runtime>
where
	State: SgxExternalitiesTrait,
	Runtime: frame_system::Config + pallet_sudo::Config,
{
	type AccountId = Runtime::AccountId;

	fn get_root(state: &mut State) -> Self::AccountId {
		state.execute_with(|| pallet_sudo::Pallet::<Runtime>::key().expect("No root account"))
	}

	fn get_enclave_account(state: &mut State) -> Self::AccountId {
		state.execute_with(enclave_signer_account::<Self::AccountId>)
	}
}

impl<TCS, G, State, Runtime, AccountId> SystemPalletAccountInterface<State, AccountId>
	for Stf<TCS, G, State, Runtime>
where
	State: SgxExternalitiesTrait,
	Runtime: frame_system::Config<AccountId = AccountId>,
	AccountId: Encode,
{
	type Index = Runtime::Index;
	type AccountData = Runtime::AccountData;

	fn get_account_nonce(state: &mut State, account: &AccountId) -> Self::Index {
		state.execute_with(|| {
			let nonce = frame_system::Pallet::<Runtime>::account_nonce(account);
			debug!("Account {} nonce is {:?}", account_id_to_string(account), nonce);
			nonce
		})
	}

	fn get_account_data(state: &mut State, account: &AccountId) -> Self::AccountData {
		state.execute_with(|| frame_system::Pallet::<Runtime>::account(account).data)
	}
}

impl<TCS, G, State, Runtime> SystemPalletEventInterface<State> for Stf<TCS, G, State, Runtime>
where
	State: SgxExternalitiesTrait,
	Runtime: frame_system::Config,
{
	type EventRecord = frame_system::EventRecord<Runtime::RuntimeEvent, Runtime::Hash>;
	type EventIndex = u32; // For some reason this is not a pub type in frame_system
	type BlockNumber = Runtime::BlockNumber;
	type Hash = Runtime::Hash;

	fn get_events(state: &mut State) -> Vec<Box<Self::EventRecord>> {
		// Fixme: Not nice to have to call collect here, but we can't use impl Iterator<..>
		// in trait method return types yet, see:
		// https://rust-lang.github.io/impl-trait-initiative/RFCs/rpit-in-traits.html
		state.execute_with(|| frame_system::Pallet::<Runtime>::read_events_no_consensus().collect())
	}

	fn get_event_count(state: &mut State) -> Self::EventIndex {
		state.execute_with(|| frame_system::Pallet::<Runtime>::event_count())
	}

	fn get_event_topics(
		state: &mut State,
		topic: &Self::Hash,
	) -> Vec<(Self::BlockNumber, Self::EventIndex)> {
		state.execute_with(|| frame_system::Pallet::<Runtime>::event_topics(topic))
	}

	fn reset_events(state: &mut State) {
		state.execute_with(|| frame_system::Pallet::<Runtime>::reset_events())
	}
}

impl<TCS, G, State, Runtime, ParentchainHeader>
	ParentchainPalletInstancesInterface<State, ParentchainHeader> for Stf<TCS, G, State, Runtime>
where
	State: SgxExternalitiesTrait,
	Runtime: frame_system::Config<Header = ParentchainHeader, AccountId = AccountId, Hash = Hash>
		+ pallet_parentchain::Config<ParentchainInstanceIntegritee>
		+ pallet_parentchain::Config<ParentchainInstanceTargetA>
		+ pallet_parentchain::Config<ParentchainInstanceTargetB>,
	<<Runtime as frame_system::Config>::Lookup as StaticLookup>::Source: From<AccountId>,
	ParentchainHeader: Debug,
{
	type Error = StfError;

	fn update_parentchain_integritee_block(
		state: &mut State,
		header: ParentchainHeader,
	) -> Result<(), Self::Error> {
		trace!("updating integritee parentchain block : {:?}", header);
		state.execute_with(|| {
			pallet_parentchain::Call::<Runtime, ParentchainInstanceIntegritee>::set_block { header }
				.dispatch_bypass_filter(Runtime::RuntimeOrigin::root())
				.map_err(|e| {
					Self::Error::Dispatch(format!(
						"Update parentchain integritee block error: {:?}",
						e.error
					))
				})
		})?;
		Ok(())
	}

	fn update_parentchain_target_a_block(
		state: &mut State,
		header: ParentchainHeader,
	) -> Result<(), Self::Error> {
		trace!("updating target_a parentchain block: {:?}", header);
		state.execute_with(|| {
			pallet_parentchain::Call::<Runtime, ParentchainInstanceTargetA>::set_block { header }
				.dispatch_bypass_filter(Runtime::RuntimeOrigin::root())
				.map_err(|e| {
					Self::Error::Dispatch(format!(
						"Update parentchain target_a block error: {:?}",
						e.error
					))
				})
		})?;
		Ok(())
	}

	fn update_parentchain_target_b_block(
		state: &mut State,
		header: ParentchainHeader,
	) -> Result<(), Self::Error> {
		trace!("updating target_b parentchain block: {:?}", header);
		state.execute_with(|| {
			pallet_parentchain::Call::<Runtime, ParentchainInstanceTargetB>::set_block { header }
				.dispatch_bypass_filter(Runtime::RuntimeOrigin::root())
				.map_err(|e| {
					Self::Error::Dispatch(format!(
						"Update parentchain target_b block error: {:?}",
						e.error
					))
				})
		})?;
		Ok(())
	}

	fn init_shard_vault_account(
		state: &mut State,
		vault: AccountId,
		parentchain_id: ParentchainId,
	) -> Result<(), Self::Error> {
		if let Some((existing_vault, existing_id)) =
			Self::get_shard_vault_ensure_single_parentchain(state)?
		{
			if existing_id != parentchain_id {
				return Err(Self::Error::ShardVaultOnMultipleParentchainsNotAllowed)
			}
			if existing_vault != vault {
				return Err(Self::Error::ChangingShardVaultAccountNotAllowed)
			}
			warn!("attempting to init shard vault which has already been initialized");
			return Ok(())
		}
		state.execute_with(|| match parentchain_id {
			ParentchainId::Integritee => pallet_parentchain::Call::<
				Runtime,
				ParentchainInstanceIntegritee,
			>::init_shard_vault {
				account: vault,
			}
			.dispatch_bypass_filter(Runtime::RuntimeOrigin::root())
			.map_err(|e| {
				Self::Error::Dispatch(format!("Init shard vault account error: {:?}", e.error))
			}),
			ParentchainId::TargetA =>
				pallet_parentchain::Call::<Runtime, ParentchainInstanceTargetA>::init_shard_vault {
					account: vault,
				}
				.dispatch_bypass_filter(Runtime::RuntimeOrigin::root())
				.map_err(|e| {
					Self::Error::Dispatch(format!("Init shard vault account error: {:?}", e.error))
				}),
			ParentchainId::TargetB =>
				pallet_parentchain::Call::<Runtime, ParentchainInstanceTargetB>::init_shard_vault {
					account: vault,
				}
				.dispatch_bypass_filter(Runtime::RuntimeOrigin::root())
				.map_err(|e| {
					Self::Error::Dispatch(format!("Init shard vault account error: {:?}", e.error))
				}),
		})?;
		Ok(())
	}

	fn set_creation_block(
		state: &mut State,
		header: ParentchainHeader,
		parentchain_id: ParentchainId,
	) -> Result<(), Self::Error> {
		state.execute_with(|| match parentchain_id {
			ParentchainId::Integritee => pallet_parentchain::Call::<
				Runtime,
				ParentchainInstanceIntegritee,
			>::set_creation_block {
				header,
			}
			.dispatch_bypass_filter(Runtime::RuntimeOrigin::root())
			.map_err(|e| {
				Self::Error::Dispatch(format!("Init shard vault account error: {:?}", e.error))
			}),
			ParentchainId::TargetA => pallet_parentchain::Call::<
				Runtime,
				ParentchainInstanceTargetA,
			>::set_creation_block {
				header,
			}
			.dispatch_bypass_filter(Runtime::RuntimeOrigin::root())
			.map_err(|e| {
				Self::Error::Dispatch(format!("Init shard vault account error: {:?}", e.error))
			}),
			ParentchainId::TargetB => pallet_parentchain::Call::<
				Runtime,
				ParentchainInstanceTargetB,
			>::set_creation_block {
				header,
			}
			.dispatch_bypass_filter(Runtime::RuntimeOrigin::root())
			.map_err(|e| {
				Self::Error::Dispatch(format!("Init shard vault account error: {:?}", e.error))
			}),
		})?;
		Ok(())
	}

	fn set_genesis_hash(
		state: &mut State,
		genesis_hash: Hash,
		parentchain_id: ParentchainId,
	) -> Result<(), Self::Error> {
		state.execute_with(|| match parentchain_id {
			ParentchainId::Integritee => pallet_parentchain::Call::<
				Runtime,
				ParentchainInstanceIntegritee,
			>::init_parentchain_genesis_hash {
				genesis: genesis_hash,
			}
			.dispatch_bypass_filter(Runtime::RuntimeOrigin::root())
			.map_err(|e| Self::Error::Dispatch(format!("Init genesis hash error: {:?}", e.error))),
			ParentchainId::TargetA => pallet_parentchain::Call::<
				Runtime,
				ParentchainInstanceTargetA,
			>::init_parentchain_genesis_hash {
				genesis: genesis_hash,
			}
			.dispatch_bypass_filter(Runtime::RuntimeOrigin::root())
			.map_err(|e| Self::Error::Dispatch(format!("Init genesis hash error: {:?}", e.error))),
			ParentchainId::TargetB => pallet_parentchain::Call::<
				Runtime,
				ParentchainInstanceTargetB,
			>::init_parentchain_genesis_hash {
				genesis: genesis_hash,
			}
			.dispatch_bypass_filter(Runtime::RuntimeOrigin::root())
			.map_err(|e| Self::Error::Dispatch(format!("Init genesis hash error: {:?}", e.error))),
		})?;
		Ok(())
	}

	fn get_shard_vault_ensure_single_parentchain(
		state: &mut State,
	) -> Result<Option<(AccountId, ParentchainId)>, Self::Error> {
		state.execute_with(|| {
			let vaults = get_shard_vaults();
			match vaults.len() {
				0 => Ok(None),
				1 => Ok(Some(vaults[0].clone())),
				_ => Err(Self::Error::Dispatch(format!(
					"shard vault assigned to more than one parentchain: {:?}",
					vaults
				))),
			}
		})
	}
}

/// Creates valid enclave account with a balance that is above the existential deposit.
/// !! Requires a root to be set.
fn create_enclave_self_account<Runtime, AccountId>(
	enclave_account: AccountId,
) -> Result<(), StfError>
where
	Runtime: frame_system::Config<AccountId = AccountId> + pallet_balances::Config,
	<<Runtime as frame_system::Config>::Lookup as StaticLookup>::Source: From<AccountId>,
	Runtime::Balance: From<u32>,
{
	pallet_balances::Call::<Runtime>::force_set_balance {
		who: enclave_account.into(),
		new_free: 1000.into(),
	}
	.dispatch_bypass_filter(Runtime::RuntimeOrigin::root())
	.map_err(|e| {
		StfError::Dispatch(format!("Set Balance for enclave signer account error: {:?}", e.error))
	})
	.map(|_| ())
}
