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

use crate::{error::Error, executor::Executor, IndirectCallsExecutor};
use codec::{Decode, Encode};
use ita_stf::{TrustedCall, TrustedOperation};
use itp_node_api::{
	api_client::ParentchainUncheckedExtrinsic,
	metadata::{
		pallet_balances::BalancesCallIndexes, provider::AccessNodeMetadata, Error as MetadataError,
		NodeMetadataTrait,
	},
};
use itp_sgx_crypto::{key_repository::AccessKey, ShieldingCryptoDecrypt, ShieldingCryptoEncrypt};
use itp_stf_executor::traits::StfEnclaveSigning;
use itp_stf_primitives::types::{AccountId, ShardIdentifier};
use itp_top_pool_author::traits::AuthorApi;
use itp_types::{TransferFn, TransferMultiAddress, H256, AccountLookup, StaticLookup};
use log::{debug, info};
use sp_runtime::traits::AccountIdLookup;

pub struct Transfer {}

impl<ShieldingKeyRepository, StfEnclaveSigner, TopPoolAuthor, NodeMetadataProvider>
	Executor<ShieldingKeyRepository, StfEnclaveSigner, TopPoolAuthor, NodeMetadataProvider>
	for Transfer
where
	ShieldingKeyRepository: AccessKey,
	<ShieldingKeyRepository as AccessKey>::KeyType: ShieldingCryptoDecrypt<Error = itp_sgx_crypto::Error>
		+ ShieldingCryptoEncrypt<Error = itp_sgx_crypto::Error>,
	StfEnclaveSigner: StfEnclaveSigning,
	TopPoolAuthor: AuthorApi<H256, H256> + Send + Sync + 'static,
	NodeMetadataProvider: AccessNodeMetadata,
	NodeMetadataProvider::MetadataType: NodeMetadataTrait,
{
    type Call = TransferFn;

    fn call_index(&self, call: &Self::Call) -> [u8; 2] {
        call.0
    }

    fn call_index_from_metadata(
            &self,
            metadata_type: &<NodeMetadataProvider as AccessNodeMetadata>::MetadataType,
        ) -> Result<[u8; 2], MetadataError> {
            metadata_type.transfer_call_indexes()
    }
    
    fn execute(
            &self,
            context: &IndirectCallsExecutor<
                ShieldingKeyRepository,
                StfEnclaveSigner,
                TopPoolAuthor,
                NodeMetadataProvider,
            >,
            extrinsic: ParentchainUncheckedExtrinsic<Self::Call>,
        ) -> Result<(), Error> {
        let (call, _transfer_multi_address, amount) = extrinsic.function;

        let sender_account: AccountId =
            extrinsic.signature
            .map(|signature| AccountLookup::lookup(signature.0))
            .ok_or(Error::Other("Error getting signature tuple from extrinsic".into()))?
            .map_err(|_| Error::Other("Error getting sender AccountId from signature tuple".into()))?;
        
        info!("Found Transfer extrinsic in block: \nCall: {:?}, \nAccount of Sender: {:?}, \nAmount: {}", call, sender_account, amount);
        // Take the first shard as a hack to just basically say use `any shard`
        let shard = context.top_pool_author.get_shards().into_iter().next().ok_or(Error::Other("Shard list empty for this context".into()))?;
        let enclave_account_id = context.stf_enclave_signer.get_enclave_account()?;
        let trusted_call = TrustedCall::balance_shield(enclave_account_id, sender_account, amount);
        let shielding_key = context.shielding_key_repo.retrieve_key()?;

        let signed_trusted_call =
			context.stf_enclave_signer.sign_call_with_self(&trusted_call, &shard)?;
        let trusted_operation = TrustedOperation::indirect_call(signed_trusted_call);
        // Encrypt and Submit
        let encrypted_trusted_call = shielding_key.encrypt(&trusted_operation.encode())?;
        context.submit_trusted_call(shard, encrypted_trusted_call);

        Ok(())
    }
}