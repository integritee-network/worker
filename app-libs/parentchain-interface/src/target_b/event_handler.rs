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
use codec::Encode;
use ita_assets_map::{AssetId, AssetTranslation};
use ita_sgx_runtime::Balance;
use ita_stf::{Getter, TrustedCall, TrustedCallSigned};
use itc_parentchain_indirect_calls_executor::error::Error;
use itp_stf_primitives::{traits::IndirectExecutor, types::TrustedOperation};
use itp_types::parentchain::{
	AccountId, BalanceTransfer, FilterEvents, ForeignAssetsTransferred, HandleParentchainEvents,
	Hash, NativeAssetsTransferred, ParentchainError, ParentchainId,
};
use itp_utils::hex::hex_encode;
use log::*;

pub struct ParentchainEventHandler {}

impl ParentchainEventHandler {
	fn shield_funds<Executor: IndirectExecutor<TrustedCallSigned, Error>>(
		executor: &Executor,
		account: &AccountId,
		amount: Balance,
		maybe_asset_id: Option<AssetId>,
	) -> Result<(), Error> {
		trace!(
			"[TargetB] shielding for {:?} amount {} asset id: {:?}",
			account,
			amount,
			maybe_asset_id
		);
		let shard = executor.get_default_shard();
		// todo: ensure this parentchain is assigned for the shard vault!

		let trusted_call = if let Some(asset_id) = maybe_asset_id {
			TrustedCall::assets_shield(
				executor.get_enclave_account()?,
				account.clone(),
				asset_id,
				amount,
				ParentchainId::TargetB,
			)
		} else {
			TrustedCall::balance_shield(
				executor.get_enclave_account()?,
				account.clone(),
				amount,
				ParentchainId::TargetB,
			)
		};
		let signed_trusted_call = executor.sign_call_with_self(&trusted_call, &shard)?;
		let trusted_operation =
			TrustedOperation::<TrustedCallSigned, Getter>::indirect_call(signed_trusted_call);

		let encrypted_trusted_call = executor.encrypt(&trusted_operation.encode())?;
		executor.submit_trusted_call(shard, encrypted_trusted_call);

		Ok(())
	}
}

impl<Executor> HandleParentchainEvents<Executor, TrustedCallSigned, Error>
	for ParentchainEventHandler
where
	Executor: IndirectExecutor<TrustedCallSigned, Error>,
{
	fn handle_events(
		executor: &Executor,
		events: impl FilterEvents,
		vault_account: &AccountId,
		genesis_hash: Hash,
	) -> Result<(), Error> {
		trace!(
			"[TargetB] filtering balance transfer events to shard vault account: {}",
			hex_encode(vault_account.encode().as_slice())
		);
		let filter_events = events.get_events::<BalanceTransfer>();
		if let Ok(events) = filter_events {
			events
                .iter()
                .filter(|&event| event.to == *vault_account)
                .try_for_each(|event| {
                    info!("[TargetB] found balance transfer event to shard vault account: {} will shield to {}", event.amount, hex_encode(event.from.encode().as_ref()));
                    Self::shield_funds(executor, &event.from, event.amount, None)
                })
                .map_err(|_| ParentchainError::ShieldFundsFailure)?;
		}
		trace!(
			"[TargetB] filtering foreign assets transferred events to shard vault account: {}",
			hex_encode(vault_account.encode().as_slice())
		);
		let filter_foreign_asset_events = events.get_events::<ForeignAssetsTransferred>();
		if let Ok(events) = filter_foreign_asset_events {
			events
                .iter()
                .filter(|&event| event.to == *vault_account)
                .try_for_each(|event| {
                    if let Some(stf_asset_id) = AssetId::from_location(&event.asset_id, genesis_hash) {
                        info!("[TargetB] found foreign assets ({:?}) transferred event to shard vault account: {} will shield to {}", stf_asset_id, event.amount, hex_encode(event.from.encode().as_ref()));
                        Self::shield_funds(executor, &event.from, event.amount, Some(stf_asset_id))
                    } else {
                        warn!("[TargetB] unsupported asset with location ({:?}) has been transferred to shard vault account with amount of {}", event.asset_id, event.amount);
                        Ok(())
                    }
                })
                .map_err(|_: Error| ParentchainError::ShieldFundsFailure)?;
		}
		trace!(
			"[TargetB] filtering native assets transferred events to shard vault account: {}",
			hex_encode(vault_account.encode().as_slice())
		);
		let filter_native_asset_events = events.get_events::<NativeAssetsTransferred>();
		if let Ok(events) = filter_native_asset_events {
			events
				.iter()
				.filter(|&event| event.to == *vault_account)
				.try_for_each(|event| {
					if let Some(stf_asset_id) = AssetId::from_asset_hub_index(event.asset_id, genesis_hash) {
						info!("[TargetB] found native assets ({:?}) transferred event to shard vault account: {} will shield to {}", stf_asset_id, event.amount, hex_encode(event.from.encode().as_ref()));
						Self::shield_funds(executor, &event.from, event.amount, Some(stf_asset_id))
					} else {
						warn!("[TargetB] unsupported asset with id ({:?}) has been transferred to shard vault account with amount of {}", event.asset_id, event.amount);
						Ok(())
					}
				})
				.map_err(|_: Error| ParentchainError::ShieldFundsFailure)?;
		}
		Ok(())
	}
}
