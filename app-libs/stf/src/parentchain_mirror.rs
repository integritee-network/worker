use crate::helpers::{shard_vault, shielding_target_genesis_hash};
use alloc::vec::Vec;
use codec::Decode;
use frame_support::dispatch::UnfilteredDispatchable;
use ita_assets_map::{AssetId, AssetTranslation, FOREIGN_ASSETS, NATIVE_ASSETS};
use itp_pallet_storage::{
	AssetsPalletStorage, AssetsPalletStorageKeys, EnclaveBridgeStorage, EnclaveBridgeStorageKeys,
	ForeignAssetsPalletStorage, ForeignAssetsPalletStorageKeys, SystemPalletStorage,
	SystemPalletStorageKeys,
};
use itp_sgx_runtime_primitives::types::ShardIdentifier;
use itp_stf_interface::parentchain_mirror_prefix;
use itp_types::{
	parentchain::{AccountInfo, AssetAccount, Balance, BlockNumber, ParentchainId},
	ShardSignerStatus,
};
use log::{error, info, warn};
pub struct ParentchainMirror {}

impl ParentchainMirror {
	pub fn get_shard_status(shard: &ShardIdentifier) -> Option<Vec<ShardSignerStatus>> {
		Self::get_mirrored_parentchain_storage_by_key_hash(
			EnclaveBridgeStorage::shard_status(shard),
			&ParentchainId::Integritee,
		)
	}

	pub fn push_upgradable_shard_config(
		shard: &ShardIdentifier,
		integritee_block_number: BlockNumber,
	) {
		// ensure we're assuming the correct storage encoding based on pallet version
		if Self::get_mirrored_parentchain_storage_by_key_hash::<u16>(
			<EnclaveBridgeStorage as EnclaveBridgeStorageKeys>::pallet_version(),
			&ParentchainId::Integritee,
		)
		.map_or(false, |v| v <= 1)
		{
			if let Some(config) = Self::get_mirrored_parentchain_storage_by_key_hash(
				EnclaveBridgeStorage::upgradable_shard_config(shard),
				&ParentchainId::Integritee,
			) {
				ita_sgx_runtime::ShardManagementCall::<ita_sgx_runtime::Runtime>::set_shard_config {
                    config,
                    parentchain_block_number: integritee_block_number,
                }
                    .dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::root())
                    // Replace with `inspect_err` once it's stable.
                    .map_err(|_| {
                        error!("Failed to mirror shard config");
                    })
                    .ok();
			} else {
				warn!("mirrored state not available: shard_config");
			}
		} else {
			warn!(
				"Parentchain Integritee pallet version mismatch. Can't sync mirrored state safely"
			);
		}
	}
	pub fn get_shard_vault_transferrable_balance(asset_id: Option<AssetId>) -> Option<Balance> {
		shard_vault().and_then(|(vault, parentchain_id)| {
			if let Some(id) = asset_id {
				let account: Option<AssetAccount> = shielding_target_genesis_hash()
					.and_then(|genesis_hash| match id.reserve_instance().unwrap_or("") {
						NATIVE_ASSETS => id.into_asset_hub_index(genesis_hash).map(|id| {
							<AssetsPalletStorage as AssetsPalletStorageKeys>::account(&id, &vault)
						}),
						FOREIGN_ASSETS =>
							id.into_location(genesis_hash).map(|loc| {
								<ForeignAssetsPalletStorage as ForeignAssetsPalletStorageKeys>::account(&loc, &vault)
							}),
						_ => None,
					})
					.and_then(|key| {
						Self::get_mirrored_parentchain_storage_by_key_hash(key, &parentchain_id)
					});
				account.map(|a| a.balance)
			} else {
				let account_info: Option<AccountInfo> =
					Self::get_mirrored_parentchain_storage_by_key_hash(
						<SystemPalletStorage as SystemPalletStorageKeys>::account(&vault),
						&parentchain_id,
					);
				account_info.map(|ai| ai.data.free - ai.data.frozen)
			}
		})
	}
	fn get_mirrored_parentchain_storage_by_key_hash<V: Decode>(
		key: Vec<u8>,
		parentchain_id: &ParentchainId,
	) -> Option<V> {
		let mut prefixed_key = parentchain_mirror_prefix(parentchain_id).as_bytes().to_vec();
		prefixed_key.extend(key);
		if let Some(value_encoded) = sp_io::storage::get(&prefixed_key) {
			if let Ok(value) = Decode::decode(&mut value_encoded.as_slice()) {
				Some(value)
			} else {
				error!("could not decode state for key {:x?}", prefixed_key);
				None
			}
		} else {
			info!("key not found in state {:x?}", prefixed_key);
			None
		}
	}
}
