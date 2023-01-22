// Copyright 2020-2023 Litentry Technologies GmbH.
// This file is part of Litentry.
//
// Litentry is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Litentry is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Litentry.  If not, see <https://www.gnu.org/licenses/>.

use crate::{error::Error, executor::Executor, IndirectCallsExecutor};
use codec::{Decode, Encode};
use ita_stf::{TrustedCall, TrustedOperation};
use itp_node_api::{
	api_client::ParentchainUncheckedExtrinsic,
	metadata::{
		pallet_teerex::TeerexCallIndexes, provider::AccessNodeMetadata, Error as MetadataError,
		NodeMetadataTrait,
	},
};
use itp_sgx_crypto::{key_repository::AccessKey, ShieldingCryptoDecrypt, ShieldingCryptoEncrypt};
use itp_stf_executor::traits::StfEnclaveSigning;
use itp_stf_primitives::types::AccountId;
use itp_top_pool_author::traits::AuthorApi;
use itp_types::{ShieldFundsFn, H256};
use log::{debug, info};

pub struct ShieldFunds {}

impl<ShieldingKeyRepository, StfEnclaveSigner, TopPoolAuthor, NodeMetadataProvider>
	Executor<ShieldingKeyRepository, StfEnclaveSigner, TopPoolAuthor, NodeMetadataProvider>
	for ShieldFunds
where
	ShieldingKeyRepository: AccessKey,
	<ShieldingKeyRepository as AccessKey>::KeyType: ShieldingCryptoDecrypt<Error = itp_sgx_crypto::Error>
		+ ShieldingCryptoEncrypt<Error = itp_sgx_crypto::Error>,
	StfEnclaveSigner: StfEnclaveSigning,
	TopPoolAuthor: AuthorApi<H256, H256> + Send + Sync + 'static,
	NodeMetadataProvider: AccessNodeMetadata,
	NodeMetadataProvider::MetadataType: NodeMetadataTrait,
{
	type Call = ShieldFundsFn;

	fn call_index(&self, call: Self::Call) -> [u8; 2] {
		call.0
	}

	fn call_index_from_metadata(
		&self,
		metadata_type: &NodeMetadataProvider::MetadataType,
	) -> Result<[u8; 2], MetadataError> {
		metadata_type.shield_funds_call_indexes()
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
		let (call, account_encrypted, amount, shard) = extrinsic.function;
		info!("Found ShieldFunds extrinsic in block: \nCall: {:?} \nAccount Encrypted {:?} \nAmount: {} \nShard: {}",
        	call, account_encrypted, amount, bs58::encode(shard.encode()).into_string());

		debug!("decrypt the account id");

		let shielding_key = context.shielding_key_repo.retrieve_key()?;
		let account_vec = shielding_key.decrypt(&account_encrypted)?;

		let account = AccountId::decode(&mut account_vec.as_slice())?;

		let enclave_account_id = context.stf_enclave_signer.get_enclave_account()?;
		let trusted_call = TrustedCall::balance_shield(enclave_account_id, account, amount);
		let signed_trusted_call =
			context.stf_enclave_signer.sign_call_with_self(&trusted_call, &shard)?;
		let trusted_operation = TrustedOperation::indirect_call(signed_trusted_call);

		let encrypted_trusted_call = shielding_key.encrypt(&trusted_operation.encode())?;
		context.submit_trusted_call(shard, encrypted_trusted_call);
		Ok(())
	}
}
