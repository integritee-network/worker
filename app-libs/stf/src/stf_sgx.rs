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
use crate::test_genesis::{test_genesis_endowees, test_genesis_setup};
use crate::{
	helpers::{
		enclave_signer_account, get_shard_vaults, shard_creation_info, shard_vault,
		shielding_target_genesis_hash,
	},
	parentchain_mirror::ParentchainMirror,
	Stf, TrustedCall, TrustedCallSigned, ENCLAVE_ACCOUNT_KEY,
};
use codec::{Decode, Encode};
use frame_support::traits::{OnTimestampSet, OriginTrait, UnfilteredDispatchable};
use ita_assets_map::{AssetId, AssetTranslation, FOREIGN_ASSETS, NATIVE_ASSETS};
use ita_parentchain_specs::MinimalChainSpec;
use ita_sgx_runtime::{
	Assets, ParentchainInstanceIntegritee, ParentchainInstanceTargetA, ParentchainInstanceTargetB,
	ShardManagement, ShardMode, System,
};
use itp_node_api::metadata::{provider::AccessNodeMetadata, NodeMetadataTrait};
use itp_pallet_storage::{
	AssetsPalletStorage, AssetsPalletStorageKeys, EnclaveBridgeStorage, EnclaveBridgeStorageKeys,
	ForeignAssetsPalletStorage, ForeignAssetsPalletStorageKeys, SidechainPalletStorage,
	SidechainPalletStorageKeys, SystemPalletStorage, SystemPalletStorageKeys,
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
use itp_types::parentchain::{AccountId, BlockNumber, Hash, Index, ParentchainCall, ParentchainId};
use itp_utils::{hex::hex_encode, stringify::account_id_to_string};
use log::*;
use sp_runtime::traits::StaticLookup;
use std::{fmt::Debug, format, prelude::v1::*, sync::Arc, vec};

/// Maximum number of accounts to retire per block.
/// chose conservatively as we don't limit execution time here but don't want to cause forks by all means.
/// Moreover, this means a heavy burst for the parentchain too, so be gentle
const MAX_ACCOUNT_RETIREMENTS_PER_BLOCK: usize = 10;

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
		state: &mut State,
		parentchain_id: &ParentchainId,
		shard: &ShardIdentifier,
	) -> Vec<Vec<u8>> {
		state.execute_with(|| {
			match parentchain_id {
				ParentchainId::Integritee => {
					let mut keys = vec![
						<EnclaveBridgeStorage as EnclaveBridgeStorageKeys>::pallet_version(),
						EnclaveBridgeStorage::shard_status(*shard),
						EnclaveBridgeStorage::upgradable_shard_config(*shard),
						<SidechainPalletStorage as EnclaveBridgeStorageKeys>::pallet_version(),
						SidechainPalletStorage::latest_sidechain_block_confirmation(*shard),
					];
					// mirror native AccountInfo for vault if shielding target
					if let Some((vault, shielding_target)) = shard_vault() {
						if shielding_target == ParentchainId::Integritee {
							keys.push(<SystemPalletStorage as SystemPalletStorageKeys>::account(
								&vault,
							));
						}
					}
					keys
				},
				ParentchainId::TargetA => {
					let mut keys = vec![];
					// mirror native AccountInfo for vault if shielding target
					if let Some((vault, shielding_target)) = shard_vault() {
						if shielding_target == ParentchainId::TargetA {
							keys.push(<SystemPalletStorage as SystemPalletStorageKeys>::account(
								&vault,
							));
						}
					}
					keys
				},
				ParentchainId::TargetB => {
					let mut keys = vec![];
					if let Some((vault, shielding_target)) = shard_vault() {
						if shielding_target == ParentchainId::TargetB {
							// mirror asset balances for vault if shielding target
							let genesis_hash = shielding_target_genesis_hash().unwrap_or_default();
							keys.extend(AssetId::all_shieldable(genesis_hash).iter().filter_map(
								|asset_id| match asset_id.reserve_instance().unwrap_or("") {
									NATIVE_ASSETS =>
										asset_id.into_asset_hub_index(genesis_hash).map(|id| {
											<AssetsPalletStorage as AssetsPalletStorageKeys>::account(
                                                &id, &vault,
                                            )
										}),
									FOREIGN_ASSETS =>
										asset_id.into_location(genesis_hash).map(|loc| {
											<ForeignAssetsPalletStorage as ForeignAssetsPalletStorageKeys>::account(&loc, &vault)
										}),
									_ => None,
								},
							));
							// mirror native AccountInfo for vault if shielding target
							keys.push(<SystemPalletStorage as SystemPalletStorageKeys>::account(
								&vault,
							));
						};
					}
					keys
				},
			}
		})
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

	fn on_initialize(
		state: &mut State,
		shard: &ShardIdentifier,
		integritee_block_number: BlockNumber,
		now: Moment,
	) -> Result<(), Self::Error> {
		debug!(
			"on_initialize called at epoch {} based on integritee block {}",
			now, integritee_block_number
		);
		state.execute_with(|| {
			// as pallet_timestamp doesn't export set_timestamp in no_std, we need to re-build the same behaviour
			sp_io::storage::set(&storage_value_key("Timestamp", "Now"), &now.encode());
			sp_io::storage::set(&storage_value_key("Timestamp", "DidUpdate"), &true.encode());
			<Runtime::OnTimestampSet as OnTimestampSet<_>>::on_timestamp_set(now.into());
			ParentchainMirror::push_upgradable_shard_config(shard, integritee_block_number);
			let vault_transferrable_balance =
				ParentchainMirror::get_shard_vault_transferrable_balance(None).unwrap_or_default();
			debug!(
				"on_initialize: shard vault native transferrable balance: {}",
				vault_transferrable_balance
			);
			for id in AssetId::all_shieldable(shielding_target_genesis_hash().unwrap_or_default()) {
				let balance = ParentchainMirror::get_shard_vault_transferrable_balance(Some(id))
					.unwrap_or_default();
				debug!("on_initialize: shard vault {:?} transferrable balance: {}", id, balance);
			}
			if ShardManagement::shard_mode() == ShardMode::Initializing {
				set_shard_mode(ShardMode::Normal);
			}
		});
		Ok(())
	}

	fn maintenance_mode_tasks(
		state: &mut State,
		shard: &ShardIdentifier,
		integritee_block_number: BlockNumber,
		calls: &mut Vec<ParentchainCall>,
		node_metadata_repo: Arc<NodeMetadataRepository>,
	) -> Result<(), Self::Error> {
		state.execute_with(|| {
            let maintenance_mode_age = integritee_block_number.saturating_sub(
                ShardManagement::upgradable_shard_config()
                    .map(|(_config, updated_at)| updated_at)
                    .unwrap_or(integritee_block_number),
            );
            if maintenance_mode_age
                >= MinimalChainSpec::maintenance_mode_duration_before_retirement(
                shielding_target_genesis_hash().unwrap_or_default(),
            ) {
                warn!("Maintenance mode has expired. Executing shard retirement tasks");
                // set the sticky flag, irrevocable!!!
                set_shard_mode(ShardMode::Retired);
                let mut accounts_to_ignore = Vec::new();
                accounts_to_ignore.push(enclave_signer_account());
                #[cfg(feature = "test")]
                accounts_to_ignore.extend(
                    test_genesis_endowees()
                        .iter()
                        .map(|(a, _)| a.clone())
                        .collect::<Vec<AccountId>>(),
                );
                if let Some(validateers) =
                    ParentchainMirror::get_shard_status(shard).map(|shard_status| {
                        shard_status
                            .iter()
                            .map(|signer_status| signer_status.signer.clone())
                            .collect::<Vec<AccountId>>()
                    }) {
                    accounts_to_ignore.extend(validateers);
                }

                let mut enclave_nonce =
                    System::account_nonce(enclave_signer_account::<AccountId>());

                frame_system::Account::<ita_sgx_runtime::Runtime>::iter_keys()
                    .filter(|account| !accounts_to_ignore.contains(account))
                    .take(MAX_ACCOUNT_RETIREMENTS_PER_BLOCK)
                    .for_each(|account| {
                        retire_account(account, &mut enclave_nonce, calls, shard, node_metadata_repo.clone());
                    });
                Ok(())
            } else {
                info!(
					"Maintenance mode is active and irrevocable shard retirement will start in {} parentchain blocks",
					MinimalChainSpec::maintenance_mode_duration_before_retirement(
						shielding_target_genesis_hash().unwrap_or_default(),
					) - maintenance_mode_age
				);
                Ok(())
            }
        })
	}

	fn on_finalize(_state: &mut State) -> Result<(), Self::Error> {
		trace!("on_finalize called");

		Ok(())
	}
}

fn retire_account<NodeMetadataRepository>(
	account: AccountId,
	enclave_nonce: &mut Index,
	calls: &mut Vec<ParentchainCall>,
	shard: &ShardIdentifier,
	node_metadata_repo: Arc<NodeMetadataRepository>,
) where
	NodeMetadataRepository: AccessNodeMetadata,
	NodeMetadataRepository::MetadataType: NodeMetadataTrait,
{
	// we won't put these calls through the TOP pool but we will use the handy ExecuteCall trait to execute directly. Therefore,
	// no signature check will happen. Still, we need to supply that field with a fake value.
	let fake_signature = Signature::Sr25519([0u8; 64].as_slice().try_into().expect("must work"));
	let genesis_hash = shielding_target_genesis_hash().unwrap_or_default();
	info!("force unshield all for {:?}", account_id_to_string(&account));
	for asset_id in AssetId::all_shieldable(genesis_hash) {
		if Assets::balance(asset_id, &account) > 0 {
			info!("  force unshield asset {:?} balance", asset_id);
			let tcs = TrustedCallSigned {
				call: TrustedCall::force_unshield_all(
					enclave_signer_account(),
					account.clone(),
					Some(asset_id),
				),
				nonce: *enclave_nonce,
				delegate: None,
				signature: fake_signature.clone(),
			};
			// Replace with `inspect_err` once it's stable.
			tcs.execute(calls, shard, node_metadata_repo.clone())
				.map_err(|e| {
					error!(
						"Failed to force-unshield {:?} for {}: {:?}",
						asset_id,
						account_id_to_string(&account),
						e
					);
				})
				.ok();
			*enclave_nonce += 1;
		}
	}
	if System::account(&account).data.free > 0 {
		info!("  force unshield native balance");
		let tcs = TrustedCallSigned {
			call: TrustedCall::force_unshield_all(enclave_signer_account(), account.clone(), None),
			nonce: *enclave_nonce, //nonce will no longer increase as we bypass signature check
			delegate: None,
			signature: fake_signature,
		};
		// Replace with `inspect_err` once it's stable.
		tcs.execute(calls, shard, node_metadata_repo)
			.map_err(|e| {
				error!(
					"Failed to force-unshield native for {:?}: {:?}",
					account_id_to_string(&account),
					e
				);
			})
			.ok();
		*enclave_nonce += 1;
	}
	// the account has been retired and is expected to be killed
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
			maybe_raw_state.map(|raw| hex_encode(raw))
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
				return Err(Self::Error::ShardVaultOnMultipleParentchainsNotAllowed);
			}
			if existing_vault != vault {
				return Err(Self::Error::ChangingShardVaultAccountNotAllowed);
			}
			warn!("attempting to init shard vault which has already been initialized");
			return Ok(());
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

fn set_shard_mode(mode: ShardMode) {
	let current_mode = ShardManagement::shard_mode();
	// avoid spamming log with errors
	if mode == ShardMode::Retired && current_mode == ShardMode::Retired {
		return;
	};

	ita_sgx_runtime::ShardManagementCall::<ita_sgx_runtime::Runtime>::set_shard_mode {
		new_shard_mode: mode,
	}
	.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::root())
	// Replace with `inspect_err` once it's stable.
	.map_err(|_| {
		error!("Failed to set shard mode to: {:?}", mode);
	})
	.ok();
}
