/*
	Copyright 2021 Integritee AG

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
use alloc::{boxed::Box, sync::Arc};
use codec::{Decode, Encode};
use core::fmt::Debug;
use itp_node_api::metadata::metadata_mocks::NodeMetadataMock;
use itp_node_api_metadata_provider::NodeMetadataRepository;
use itp_sgx_externalities::{SgxExternalities, SgxExternalitiesDiffType, SgxExternalitiesTrait};
use itp_stf_interface::{
    ExecuteCall, InitState, StateCallInterface, StateGetterInterface, UpdateState,
};
use itp_stf_primitives::{
    traits::{
        GetterAuthorization, PoolTransactionValidation, TrustedCallSigning, TrustedCallVerification,
    },
    types::{KeyPair, Nonce, TrustedOperation},
};
use itp_types::{parentchain::{ParentchainCall, ParentchainId}, AccountId, Balance, Index, Moment, ShardIdentifier, Signature};
use log::*;
use sp_core::{sr25519, Pair};
use sp_runtime::transaction_validity::{
    TransactionValidityError, UnknownTransaction, ValidTransaction,
};
use sp_std::{vec, vec::Vec};
use std::{thread::sleep, time::Duration};


// a few dummy types
type NodeMetadataRepositoryMock = NodeMetadataRepository<NodeMetadataMock>;

#[derive(Debug, PartialEq, Eq)]
pub enum StfMockError {
    Dummy,
}
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct StfMock {
    state: SgxExternalities,
}

impl UpdateState<SgxExternalities, SgxExternalitiesDiffType> for StfMock {
    fn apply_state_diff(_state: &mut SgxExternalities, _map_update: SgxExternalitiesDiffType) {}

    fn storage_hashes_to_update_on_block(_parentchain_id: &ParentchainId) -> Vec<Vec<u8>> {
        vec![]
    }
}

impl StateCallInterface<TrustedCallSignedMock, SgxExternalities, NodeMetadataRepositoryMock>
for StfMock
{
    type Error = StfMockError;

    fn execute_call(
        state: &mut SgxExternalities,
        call: TrustedCallSignedMock,
        calls: &mut Vec<ParentchainCall>,
        node_metadata_repo: Arc<NodeMetadataRepositoryMock>,
    ) -> Result<(), Self::Error> {
        state.execute_with(|| call.execute(calls, node_metadata_repo))
    }

    fn on_initialize(_state: &mut SgxExternalities, now: Moment) -> Result<(), Self::Error> {
        trace!("on_initialize called at epoch {}", now);
        Ok(())
    }
    fn on_finalize(_state: &mut SgxExternalities) -> Result<(), Self::Error> {
        trace!("on_finalize called");
        Ok(())
    }
}

impl InitState<SgxExternalities, AccountId> for StfMock {
    fn init_state(_enclave_account: AccountId) -> SgxExternalities {
        SgxExternalities::new(Default::default())
    }
}

impl StateGetterInterface<GetterMock, SgxExternalities> for StfMock {
    fn execute_getter(_state: &mut SgxExternalities, _getter: GetterMock) -> Option<Vec<u8>> {
        Some(vec![42])
    }
}

pub type TrustedOperationMock = TrustedOperation<TrustedCallSignedMock, GetterMock>;

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum TrustedCallMock {
    noop(AccountId),
    balance_transfer(AccountId, AccountId, Balance),
    waste_time_ms(AccountId, u64),
}

impl TrustedCallMock {
    pub fn sender_account(&self) -> &AccountId {
        match self {
            Self::noop(sender_account) => sender_account,
            Self::balance_transfer(sender_account, ..) => sender_account,
            Self::waste_time_ms(sender_account, ..) => sender_account,
        }
    }
}

impl TrustedCallSigning<TrustedCallSignedMock> for TrustedCallMock {
    fn sign(
        &self,
        pair: &KeyPair,
        nonce: Index,
        mrenclave: &[u8; 32],
        shard: &ShardIdentifier,
    ) -> TrustedCallSignedMock {
        let mut payload = self.encode();
        payload.append(&mut nonce.encode());
        payload.append(&mut mrenclave.encode());
        payload.append(&mut shard.encode());

        TrustedCallSignedMock {
            call: self.clone(),
            nonce,
            signature: pair.sign(payload.as_slice()),
        }
    }
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct TrustedCallSignedMock {
    pub call: TrustedCallMock,
    pub nonce: Index,
    pub signature: Signature,
}

impl TrustedCallSignedMock {
    pub fn new(call: TrustedCallMock, nonce: Index, signature: Signature) -> Self {
        TrustedCallSignedMock { call, nonce, signature }
    }

    pub fn into_trusted_operation(
        self,
        direct: bool,
    ) -> TrustedOperation<TrustedCallSignedMock, GetterMock> {
        match direct {
            true => TrustedOperation::direct_call(self),
            false => TrustedOperation::indirect_call(self),
        }
    }
}

impl Default for TrustedCallSignedMock {
    fn default() -> Self {
        mock_trusted_call_signed(0)
    }
}

impl ExecuteCall<NodeMetadataRepositoryMock> for TrustedCallSignedMock {
    type Error = StfMockError;

    fn execute(
        self,
        _calls: &mut Vec<ParentchainCall>,
        _node_metadata_repo: Arc<NodeMetadataRepositoryMock>,
    ) -> Result<(), Self::Error> {
        match self.call {
            TrustedCallMock::noop(_) => Ok(()),
            TrustedCallMock::balance_transfer(_, _, balance) => {
                info!("touching state");
                sp_io::storage::set(b"dummy_key", &balance.encode());
                Ok(())
            }
            TrustedCallMock::waste_time_ms(_, ms) => {
                sp_io::storage::set(b"dummy_key_waste_time", &42u8.encode());
                info!("executing stf call waste_time_ms. sleeping for {}ms", ms);
                sleep(Duration::from_millis(ms));
                Ok(())
            }
        }
    }

    fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>> {
        Vec::new()
    }
}

impl TrustedCallVerification for TrustedCallSignedMock {
    fn sender_account(&self) -> &AccountId {
        self.call.sender_account()
    }

    fn nonce(&self) -> Index {
        self.nonce
    }

    fn verify_signature(&self, _mrenclave: &[u8; 32], _shard: &ShardIdentifier) -> bool {
        true
    }
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum GetterMock {
    public(PublicGetterMock),
    trusted(TrustedGetterSignedMock),
}

impl Default for GetterMock {
    fn default() -> Self {
        GetterMock::public(PublicGetterMock::some_value)
    }
}

impl PoolTransactionValidation for GetterMock {
    fn validate(&self) -> Result<ValidTransaction, TransactionValidityError> {
        Err(TransactionValidityError::Unknown(UnknownTransaction::CannotLookup))
    }
}

impl GetterAuthorization for GetterMock {
    fn is_authorized(&self) -> bool {
        match self {
            Self::trusted(tgs) => tgs.signature,
            Self::public(_) => true,
        }
    }
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum PublicGetterMock {
    some_value,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum TrustedGetterMock {
    some_value,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct TrustedGetterSignedMock {
    pub getter: TrustedGetterMock,
    pub signature: bool,
}

const MOCK_SEED: [u8; 32] = *b"34567890123456789012345678901234";

pub fn mock_key_pair() -> KeyPair {
    KeyPair::Sr25519(Box::new(sr25519::Pair::from_seed(&MOCK_SEED)))
}

pub fn mock_trusted_call_signed(nonce: Nonce) -> TrustedCallSignedMock {
    TrustedCallMock::balance_transfer(
        mock_key_pair().account_id(),
        mock_key_pair().account_id(),
        42,
    )
        .sign(&mock_key_pair(), nonce, &[0u8; 32], &ShardIdentifier::default())
}

pub fn mock_top_direct_trusted_call_signed() -> TrustedOperationMock {
    TrustedOperationMock::direct_call(mock_trusted_call_signed(0))
}

pub fn mock_top_indirect_trusted_call_signed() -> TrustedOperationMock {
    TrustedOperationMock::indirect_call(mock_trusted_call_signed(0))
}

pub fn mock_top_trusted_getter_signed() -> TrustedOperationMock {
    TrustedOperationMock::get(GetterMock::trusted(TrustedGetterSignedMock {
        getter: TrustedGetterMock::some_value,
        signature: true,
    }))
}

pub fn mock_top_public_getter() -> TrustedOperationMock {
    TrustedOperationMock::get(GetterMock::public(PublicGetterMock::some_value))
}
