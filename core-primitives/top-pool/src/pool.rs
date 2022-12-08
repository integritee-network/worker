// This file is part of Substrate.

// Copyright (C) 2018-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use crate::{
	base_pool as base, error,
	primitives::TrustedOperationSource,
	validated_pool::{ValidatedOperation, ValidatedPool},
};
use core::matches;
use ita_stf::TrustedOperation as StfTrustedOperation;
use itc_direct_rpc_server::SendRpcResponse;
use itp_stf_primitives::types::ShardIdentifier;
use itp_types::BlockHash as SidechainBlockHash;
use jsonrpc_core::futures::{channel::mpsc::Receiver, future, Future};
use sp_runtime::{
	generic::BlockId,
	traits::{self, Block as BlockT, SaturatedConversion},
	transaction_validity::{TransactionTag as Tag, TransactionValidity, TransactionValidityError},
};
use std::{collections::HashMap, format, sync::Arc, time::Instant, vec::Vec};

/// Modification notification event stream type;
pub type EventStream<H> = Receiver<H>;

/// Block hash type for a pool.
pub type BlockHash<A> = <<A as ChainApi>::Block as traits::Block>::Hash;
/// Extrinsic hash type for a pool.
pub type ExtrinsicHash<A> = <<A as ChainApi>::Block as traits::Block>::Hash;
/// Extrinsic type for a pool.
//pub type ExtrinsicFor<A> = <<A as ChainApi>::Block as traits::Block>::Extrinsic;
/// Block number type for the ChainApi
pub type NumberFor<A> = traits::NumberFor<<A as ChainApi>::Block>;
/// A type of operation stored in the pool
pub type TransactionFor<A> = Arc<base::TrustedOperation<ExtrinsicHash<A>, StfTrustedOperation>>;
/// A type of validated operation stored in the pool.
pub type ValidatedOperationFor<A> =
	ValidatedOperation<ExtrinsicHash<A>, StfTrustedOperation, <A as ChainApi>::Error>;

/// Concrete extrinsic validation and query logic.
pub trait ChainApi: Send + Sync {
	/// Block type.
	type Block: BlockT;
	/// Error type.
	type Error: From<error::Error>;
	/// Validate operation future.
	type ValidationFuture: Future<Output = Result<TransactionValidity, Self::Error>> + Send + Unpin;
	/// Body future (since block body might be remote)
	type BodyFuture: Future<Output = Result<Option<Vec<StfTrustedOperation>>, Self::Error>>
		+ Unpin
		+ Send
		+ 'static;

	/// Verify extrinsic at given block.
	fn validate_transaction(
		&self,
		source: TrustedOperationSource,
		uxt: StfTrustedOperation,
		shard: ShardIdentifier,
	) -> Self::ValidationFuture;

	/// Returns a block number given the block id.
	fn block_id_to_number(
		&self,
		at: &BlockId<Self::Block>,
	) -> Result<Option<NumberFor<Self>>, Self::Error>;

	/// Returns a block hash given the block id.
	fn block_id_to_hash(
		&self,
		at: &BlockId<Self::Block>,
	) -> Result<Option<SidechainBlockHash>, Self::Error>;

	/// Returns hash and encoding length of the extrinsic.
	fn hash_and_length(&self, uxt: &StfTrustedOperation) -> (ExtrinsicHash<Self>, usize);

	/// Returns a block body given the block id.
	fn block_body(&self, at: &BlockId<Self::Block>) -> Self::BodyFuture;
}

/// Pool configuration options.
#[derive(Debug, Clone)]
pub struct Options {
	/// Ready queue limits.
	pub ready: base::Limit,
	/// Future queue limits.
	pub future: base::Limit,
	/// Reject future operations.
	pub reject_future_operations: bool,
}

impl Default for Options {
	fn default() -> Self {
		Options {
			ready: base::Limit { count: 8192, total_bytes: 20 * 1024 * 1024 },
			future: base::Limit { count: 512, total_bytes: 1024 * 1024 },
			reject_future_operations: false,
		}
	}
}

/// Should we check that the operation is banned
/// in the pool, before we verify it?
#[derive(Copy, Clone)]
enum CheckBannedBeforeVerify {
	Yes,
	No,
}

/// Extrinsics pool that performs validation.
pub struct Pool<B: ChainApi, R>
where
	R: SendRpcResponse<Hash = ExtrinsicHash<B>>,
{
	validated_pool: Arc<ValidatedPool<B, R>>,
}

impl<B: ChainApi, R> Pool<B, R>
where
	//<<B as ChainApi>::Block as sp_runtime::traits::Block>::Hash: Serialize,
	<B as ChainApi>::Error: error::IntoPoolError,
	R: SendRpcResponse<Hash = ExtrinsicHash<B>>,
{
	/// Create a new operation pool.
	pub fn new(options: Options, api: Arc<B>, rpc_response_sender: Arc<R>) -> Self {
		Pool { validated_pool: Arc::new(ValidatedPool::new(options, api, rpc_response_sender)) }
	}

	/// Imports a bunch of unverified extrinsics to the pool
	pub async fn submit_at(
		&self,
		at: &BlockId<B::Block>,
		source: TrustedOperationSource,
		xts: impl IntoIterator<Item = StfTrustedOperation>,
		shard: ShardIdentifier,
	) -> Result<Vec<Result<ExtrinsicHash<B>, B::Error>>, B::Error> {
		let xts = xts.into_iter().map(|xt| (source, xt));
		let validated_transactions =
			self.verify(at, xts, CheckBannedBeforeVerify::Yes, shard).await?;
		Ok(self.validated_pool.submit(validated_transactions.into_values(), shard))
	}

	/// Resubmit the given extrinsics to the pool.
	///
	/// This does not check if a operation is banned, before we verify it again.
	pub async fn resubmit_at(
		&self,
		at: &BlockId<B::Block>,
		source: TrustedOperationSource,
		xts: impl IntoIterator<Item = StfTrustedOperation>,
		shard: ShardIdentifier,
	) -> Result<Vec<Result<ExtrinsicHash<B>, B::Error>>, B::Error> {
		let xts = xts.into_iter().map(|xt| (source, xt));
		let validated_transactions =
			self.verify(at, xts, CheckBannedBeforeVerify::No, shard).await?;
		Ok(self.validated_pool.submit(validated_transactions.into_values(), shard))
	}

	/// Imports one unverified extrinsic to the pool
	pub async fn submit_one(
		&self,
		at: &BlockId<B::Block>,
		source: TrustedOperationSource,
		xt: StfTrustedOperation,
		shard: ShardIdentifier,
	) -> Result<ExtrinsicHash<B>, B::Error> {
		let res = self.submit_at(at, source, std::iter::once(xt), shard).await?.pop();
		res.expect("One extrinsic passed; one result returned; qed")
	}

	/// Import a single extrinsic and starts to watch their progress in the pool.
	pub async fn submit_and_watch(
		&self,
		at: &BlockId<B::Block>,
		source: TrustedOperationSource,
		xt: StfTrustedOperation,
		shard: ShardIdentifier,
	) -> Result<ExtrinsicHash<B>, B::Error> {
		//TODO
		//let block_number = self.resolve_block_number(at)?;
		// dummy value:
		let block_number = 0;
		let (_, tx) = self
			.verify_one(at, block_number, source, xt, CheckBannedBeforeVerify::Yes, shard)
			.await;
		self.validated_pool.submit_and_watch(tx, shard)
	}

	/// Resubmit some operation that were validated elsewhere.
	pub fn resubmit(
		&self,
		revalidated_transactions: HashMap<ExtrinsicHash<B>, ValidatedOperationFor<B>>,
		shard: ShardIdentifier,
	) {
		let now = Instant::now();
		self.validated_pool.resubmit(revalidated_transactions, shard);
		log::debug!(target: "txpool",
			"Resubmitted. Took {} ms. Status: {:?}",
			now.elapsed().as_millis(),
			self.validated_pool.status(shard)
		);
	}

	/// Prunes known ready operations.
	///
	/// Used to clear the pool from operations that were part of recently imported block.
	/// The main difference from the `prune` is that we do not revalidate any operations
	/// and ignore unknown passed hashes.
	pub fn prune_known(
		&self,
		at: &BlockId<B::Block>,
		hashes: &[ExtrinsicHash<B>],
		shard: ShardIdentifier,
	) -> Result<(), B::Error> {
		// Get details of all extrinsics that are already in the pool
		#[allow(clippy::filter_map_identity)]
		// false positive. Filter map does filter because x is an option
		let in_pool_tags = self
			.validated_pool
			.extrinsics_tags(hashes, shard)
			.into_iter()
			.filter_map(|x| x)
			.flatten();

		// Prune all operations that provide given tags
		let prune_status = self.validated_pool.prune_tags(in_pool_tags, shard)?;
		let pruned_transactions =
			hashes.iter().cloned().chain(prune_status.pruned.iter().map(|tx| tx.hash));
		self.validated_pool.fire_pruned(at, pruned_transactions)
	}

	/// Prunes ready operations.
	///
	/// Used to clear the pool from operations that were part of recently imported block.
	/// To perform pruning we need the tags that each extrinsic provides and to avoid calling
	/// into runtime too often we first lookup all extrinsics that are in the pool and get
	/// their provided tags from there. Otherwise we query the runtime at the `parent` block.
	pub async fn prune(
		&self,
		at: &BlockId<B::Block>,
		_parent: &BlockId<B::Block>,
		extrinsics: &[StfTrustedOperation],
		shard: ShardIdentifier,
	) -> Result<(), B::Error> {
		log::debug!(
			target: "txpool",
			"Starting pruning of block {:?} (extrinsics: {})",
			at,
			extrinsics.len()
		);
		// Get details of all extrinsics that are already in the pool
		let in_pool_hashes =
			extrinsics.iter().map(|extrinsic| self.hash_of(extrinsic)).collect::<Vec<_>>();
		let in_pool_tags = self.validated_pool.extrinsics_tags(&in_pool_hashes, shard);

		// Zip the ones from the pool with the full list (we get pairs `(Extrinsic, Option<Vec<Tag>>)`)
		let all = extrinsics.iter().zip(in_pool_tags.into_iter());

		let mut future_tags = Vec::new();
		for (extrinsic, in_pool_tags) in all {
			match in_pool_tags {
				// reuse the tags for extrinsics that were found in the pool
				Some(tags) => future_tags.extend(tags),
				// if it's not found in the pool query the runtime at parent block
				// to get validity info and tags that the extrinsic provides.
				None => {
					let validity = self
						.validated_pool
						.api()
						.validate_transaction(
							TrustedOperationSource::InBlock,
							extrinsic.clone(),
							shard,
						)
						.await;

					if let Ok(Ok(validity)) = validity {
						future_tags.extend(validity.provides);
					}
				},
			}
		}

		self.prune_tags(at, future_tags, in_pool_hashes, shard).await
	}

	/// Prunes ready operations that provide given list of tags.
	///
	/// Given tags are assumed to be always provided now, so all operations
	/// in the Future Queue that require that particular tag (and have other
	/// requirements satisfied) are promoted to Ready Queue.
	///
	/// Moreover for each provided tag we remove operations in the pool that:
	/// 1. Provide that tag directly
	/// 2. Are a dependency of pruned operation.
	///
	/// Returns operations that have been removed from the pool and must be reverified
	/// before reinserting to the pool.
	///
	/// By removing predecessor operations as well we might actually end up
	/// pruning too much, so all removed operations are reverified against
	/// the runtime (`validate_transaction`) to make sure they are invalid.
	///
	/// However we avoid revalidating operations that are contained within
	/// the second parameter of `known_imported_hashes`. These operations
	/// (if pruned) are not revalidated and become temporarily banned to
	/// prevent importing them in the (near) future.
	pub async fn prune_tags(
		&self,
		at: &BlockId<B::Block>,
		tags: impl IntoIterator<Item = Tag>,
		known_imported_hashes: impl IntoIterator<Item = ExtrinsicHash<B>> + Clone,
		shard: ShardIdentifier,
	) -> Result<(), B::Error> {
		log::debug!(target: "txpool", "Pruning at {:?}", at);
		// Prune all operations that provide given tags
		let prune_status = match self.validated_pool.prune_tags(tags, shard) {
			Ok(prune_status) => prune_status,
			Err(e) => return Err(e),
		};

		// Make sure that we don't revalidate extrinsics that were part of the recently
		// imported block. This is especially important for UTXO-like chains cause the
		// inputs are pruned so such operation would go to future again.
		self.validated_pool
			.ban(&Instant::now(), known_imported_hashes.clone().into_iter());

		// Try to re-validate pruned operations since some of them might be still valid.
		// note that `known_imported_hashes` will be rejected here due to temporary ban.
		let pruned_hashes = prune_status.pruned.iter().map(|tx| tx.hash).collect::<Vec<_>>();
		let pruned_transactions =
			prune_status.pruned.into_iter().map(|tx| (tx.source, tx.data.clone()));

		let reverified_transactions = self
			.verify(at, pruned_transactions, CheckBannedBeforeVerify::Yes, shard)
			.await?;

		log::trace!(target: "txpool", "Pruning at {:?}. Resubmitting operations.", at);
		// And finally - submit reverified operations back to the pool

		self.validated_pool.resubmit_pruned(
			at,
			known_imported_hashes,
			pruned_hashes,
			reverified_transactions.into_values().collect(),
			shard,
		)
	}

	/// Returns operation hash
	pub fn hash_of(&self, xt: &StfTrustedOperation) -> ExtrinsicHash<B> {
		self.validated_pool.api().hash_and_length(xt).0
	}

	/// Resolves block number by id.
	fn _resolve_block_number(&self, at: &BlockId<B::Block>) -> Result<NumberFor<B>, B::Error> {
		self.validated_pool.api().block_id_to_number(at).and_then(|number| {
			number.ok_or_else(|| error::Error::InvalidBlockId(format!("{:?}", at)).into())
		})
	}

	/// Returns future that validates a bunch of operations at given block.
	async fn verify(
		&self,
		at: &BlockId<B::Block>,
		xts: impl IntoIterator<Item = (TrustedOperationSource, StfTrustedOperation)>,
		check: CheckBannedBeforeVerify,
		shard: ShardIdentifier,
	) -> Result<HashMap<ExtrinsicHash<B>, ValidatedOperationFor<B>>, B::Error> {
		//FIXME: Nicer verify
		// we need a block number to compute tx validity
		//let block_number = self.resolve_block_number(at)?;
		// dummy blocknumber
		//pub type NumberFor<A> = traits::NumberFor<<A as ChainApi>::Block>;
		let block_number = 0;

		let res = future::join_all(
			xts.into_iter()
				.map(|(source, xt)| self.verify_one(at, block_number, source, xt, check, shard)),
		)
		.await
		.into_iter()
		.collect::<HashMap<_, _>>();

		Ok(res)
	}

	/// Returns future that validates single operation at given block.
	async fn verify_one(
		&self,
		_block_id: &BlockId<B::Block>,
		//block_number: NumberFor<B>,
		block_number: i8,
		source: TrustedOperationSource,
		xt: StfTrustedOperation,
		check: CheckBannedBeforeVerify,
		shard: ShardIdentifier,
	) -> (ExtrinsicHash<B>, ValidatedOperationFor<B>) {
		let (hash, bytes) = self.validated_pool.api().hash_and_length(&xt);

		let ignore_banned = matches!(check, CheckBannedBeforeVerify::No);
		if let Err(err) = self.validated_pool.check_is_known(&hash, ignore_banned, shard) {
			return (hash, ValidatedOperation::Invalid(hash, err))
		}

		//FIXME:
		// no runtime validation check for now.
		let validation_result =
			self.validated_pool.api().validate_transaction(source, xt.clone(), shard).await;

		let status = match validation_result {
			Ok(status) => status,
			Err(e) => return (hash, ValidatedOperation::Invalid(hash, e)),
		};

		let validity = match status {
			Ok(validity) =>
				if validity.provides.is_empty() {
					ValidatedOperation::Invalid(hash, error::Error::NoTagsProvided.into())
				} else {
					ValidatedOperation::valid_at(
						block_number.saturated_into::<u64>(),
						hash,
						source,
						xt,
						bytes,
						validity,
					)
				},
			Err(TransactionValidityError::Invalid(_e)) =>
				ValidatedOperation::Invalid(hash, error::Error::InvalidTrustedOperation.into()),
			Err(TransactionValidityError::Unknown(_e)) =>
				ValidatedOperation::Unknown(hash, error::Error::UnknownTrustedOperation.into()),
		};

		(hash, validity)
	}

	/// get a reference to the underlying validated pool.
	pub fn validated_pool(&self) -> &ValidatedPool<B, R> {
		&self.validated_pool
	}
}

impl<B: ChainApi, R> Clone for Pool<B, R>
where
	<B as ChainApi>::Error: error::IntoPoolError,
	R: SendRpcResponse<Hash = ExtrinsicHash<B>>,
{
	fn clone(&self) -> Self {
		Self { validated_pool: self.validated_pool.clone() }
	}
}

#[cfg(test)]
pub mod tests {

	use super::*;
	use crate::{
		base_pool::Limit, mocks::rpc_responder_mock::RpcResponderMock,
		primitives::from_low_u64_to_be_h256,
	};
	use codec::{Decode, Encode};
	use ita_stf::{Index, TrustedCall, TrustedCallSigned, TrustedOperation};
	use itp_types::Header;
	use jsonrpc_core::{futures, futures::executor::block_on};
	use parity_util_mem::MallocSizeOf;
	use serde::Serialize;
	use sp_application_crypto::ed25519;
	use sp_core::{hash::H256, Pair};
	use sp_runtime::{
		traits::{BlakeTwo256, Extrinsic as ExtrinsicT, Hash, Verify},
		transaction_validity::{InvalidTransaction as InvalidTrustedOperation, ValidTransaction},
		MultiSignature,
	};
	use std::{collections::HashSet, sync::Mutex};

	#[derive(Clone, PartialEq, Eq, Encode, Decode, core::fmt::Debug, Serialize, MallocSizeOf)]
	pub enum Extrinsic {
		IncludeData(Vec<u8>),
		StorageChange(Vec<u8>, Option<Vec<u8>>),
		OffchainIndexSet(Vec<u8>, Vec<u8>),
		OffchainIndexClear(Vec<u8>),
	}

	impl ExtrinsicT for Extrinsic {
		type Call = Extrinsic;
		type SignaturePayload = ();

		fn is_signed(&self) -> Option<bool> {
			if let Extrinsic::IncludeData(_) = *self {
				Some(false)
			} else {
				Some(true)
			}
		}

		fn new(
			call: Self::Call,
			_signature_payload: Option<Self::SignaturePayload>,
		) -> Option<Self> {
			Some(call)
		}
	}

	/// The signature type used by accounts/transactions.
	pub type AccountSignature = ed25519::Signature;
	/// An identifier for an account on this system.
	pub type AccountId = <AccountSignature as Verify>::Signer;
	/// The hashing algorithm used.
	pub type Hashing = BlakeTwo256;
	/// The item of a block digest.
	pub type DigestItem = sp_runtime::generic::DigestItem;
	/// The digest of a block.
	pub type Digest = sp_runtime::generic::Digest;
	/// A test block.
	pub type Block = sp_runtime::generic::Block<Header, Extrinsic>;
	/// Test RPC responder
	pub type TestRpcResponder = RpcResponderMock<H256>;

	const INVALID_NONCE: Index = 254;
	const SOURCE: TrustedOperationSource = TrustedOperationSource::External;

	#[derive(Clone, Debug, Default)]
	struct TestApi {
		delay: Arc<Mutex<Option<std::sync::mpsc::Receiver<()>>>>,
		invalidate: Arc<Mutex<HashSet<H256>>>,
		clear_requirements: Arc<Mutex<HashSet<H256>>>,
		add_requirements: Arc<Mutex<HashSet<H256>>>,
	}

	impl ChainApi for TestApi {
		type Block = tests::Block;
		type Error = error::Error;
		type ValidationFuture = futures::future::Ready<error::Result<TransactionValidity>>;
		type BodyFuture = futures::future::Ready<error::Result<Option<Vec<StfTrustedOperation>>>>;

		/// Verify extrinsic at given block.
		fn validate_transaction(
			&self,
			_source: TrustedOperationSource,
			uxt: StfTrustedOperation,
			_shard: ShardIdentifier,
		) -> Self::ValidationFuture {
			let hash = self.hash_and_length(&uxt).0;
			let nonce: Index = match uxt {
				StfTrustedOperation::direct_call(signed_call) => signed_call.nonce,
				_ => 0,
			};

			// This is used to control the test flow.
			if nonce > 0 {
				let opt = self.delay.lock().unwrap().take();
				if let Some(delay) = opt {
					if delay.recv().is_err() {
						println!("Error waiting for delay!");
					}
				}
			}

			if self.invalidate.lock().unwrap().contains(&hash) {
				return futures::future::ready(Ok(InvalidTrustedOperation::Custom(0).into()))
			}

			futures::future::ready(if nonce > 254 {
				Ok(InvalidTrustedOperation::Stale.into())
			} else {
				let mut operation = ValidTransaction {
					priority: 4,
					requires: if nonce > 0 { vec![vec![nonce as u8 - 1]] } else { vec![] },
					provides: if nonce == INVALID_NONCE { vec![] } else { vec![vec![nonce as u8]] },
					longevity: 3,
					propagate: true,
				};

				if self.clear_requirements.lock().unwrap().contains(&hash) {
					operation.requires.clear();
				}

				if self.add_requirements.lock().unwrap().contains(&hash) {
					operation.requires.push(vec![128]);
				}

				Ok(Ok(operation))
			})
		}

		/// Returns a block number given the block id.
		fn block_id_to_number(
			&self,
			at: &BlockId<Self::Block>,
		) -> Result<Option<NumberFor<Self>>, Self::Error> {
			Ok(match at {
				BlockId::Number(num) => Some(*num),
				BlockId::Hash(_) => None,
			})
		}

		/// Returns a block hash given the block id.
		fn block_id_to_hash(
			&self,
			at: &BlockId<Self::Block>,
		) -> Result<Option<SidechainBlockHash>, Self::Error> {
			Ok(match at {
				BlockId::Number(num) => Some(from_low_u64_to_be_h256((*num).into())),
				BlockId::Hash(_) => None,
			})
		}

		/// Hash the extrinsic.
		fn hash_and_length(&self, uxt: &StfTrustedOperation) -> (BlockHash<Self>, usize) {
			let encoded = uxt.encode();
			let len = encoded.len();
			(tests::Hashing::hash_of(&encoded), len)
		}

		fn block_body(&self, _id: &BlockId<Self::Block>) -> Self::BodyFuture {
			futures::future::ready(Ok(None))
		}
	}

	fn to_top(call: TrustedCall, nonce: Index) -> TrustedOperation {
		let msg = &b"test-message"[..];
		let (pair, _) = ed25519::Pair::generate();

		let signature = pair.sign(&msg);
		let multi_sig = MultiSignature::from(signature);
		TrustedCallSigned::new(call, nonce, multi_sig).into_trusted_operation(true)
	}

	fn test_pool() -> Pool<TestApi, RpcResponderMock<H256>> {
		Pool::new(
			Default::default(),
			TestApi::default().into(),
			Arc::new(RpcResponderMock::<H256>::new()),
		)
	}

	#[test]
	pub fn test_should_validate_and_import_transaction() {
		// given
		let pool = test_pool();
		let shard = ShardIdentifier::default();

		// when
		let hash = block_on(pool.submit_one(
			&BlockId::Number(0),
			SOURCE,
			to_top(
				TrustedCall::balance_transfer(
					tests::AccountId::from_h256(from_low_u64_to_be_h256(1)).into(),
					tests::AccountId::from_h256(from_low_u64_to_be_h256(2)).into(),
					5,
				),
				0,
			),
			shard,
		))
		.unwrap();

		// then
		assert_eq!(
			pool.validated_pool().ready(shard).map(|v| v.hash).collect::<Vec<_>>(),
			vec![hash]
		);
	}

	#[test]
	pub fn test_should_reject_if_temporarily_banned() {
		// given
		let pool = test_pool();
		let shard = ShardIdentifier::default();
		let top = to_top(
			TrustedCall::balance_transfer(
				tests::AccountId::from_h256(from_low_u64_to_be_h256(1)).into(),
				tests::AccountId::from_h256(from_low_u64_to_be_h256(2)).into(),
				5,
			),
			0,
		);

		// when
		pool.validated_pool.rotator().ban(&Instant::now(), vec![pool.hash_of(&top)]);
		let res = block_on(pool.submit_one(&BlockId::Number(0), SOURCE, top, shard));
		assert_eq!(pool.validated_pool().status(shard).ready, 0);
		assert_eq!(pool.validated_pool().status(shard).future, 0);

		// then
		assert!(matches!(res.unwrap_err(), error::Error::TemporarilyBanned));
	}

	#[test]
	pub fn test_should_notify_about_pool_events() {
		let (stream, hash0, hash1) = {
			// given
			let pool = test_pool();
			let shard = ShardIdentifier::default();
			let stream = pool.validated_pool().import_notification_stream();

			// when
			let hash0 = block_on(pool.submit_one(
				&BlockId::Number(0),
				SOURCE,
				to_top(
					TrustedCall::balance_transfer(
						tests::AccountId::from_h256(from_low_u64_to_be_h256(1)).into(),
						tests::AccountId::from_h256(from_low_u64_to_be_h256(2)).into(),
						5,
					),
					0,
				),
				shard,
			))
			.unwrap();
			let hash1 = block_on(pool.submit_one(
				&BlockId::Number(0),
				SOURCE,
				to_top(
					TrustedCall::balance_transfer(
						tests::AccountId::from_h256(from_low_u64_to_be_h256(1)).into(),
						tests::AccountId::from_h256(from_low_u64_to_be_h256(2)).into(),
						5,
					),
					1,
				),
				shard,
			))
			.unwrap();
			// future doesn't count
			let _hash = block_on(pool.submit_one(
				&BlockId::Number(0),
				SOURCE,
				to_top(
					TrustedCall::balance_transfer(
						tests::AccountId::from_h256(from_low_u64_to_be_h256(1)).into(),
						tests::AccountId::from_h256(from_low_u64_to_be_h256(2)).into(),
						5,
					),
					3,
				),
				shard,
			))
			.unwrap();

			assert_eq!(pool.validated_pool().status(shard).ready, 2);
			assert_eq!(pool.validated_pool().status(shard).future, 1);

			(stream, hash0, hash1)
		};

		// then
		let mut it = futures::executor::block_on_stream(stream);
		assert_eq!(it.next(), Some(hash0));
		assert_eq!(it.next(), Some(hash1));
		assert_eq!(it.next(), None);
	}

	#[test]
	pub fn test_should_clear_stale_transactions() {
		// given
		let pool = test_pool();
		let shard = ShardIdentifier::default();
		let hash1 = block_on(pool.submit_one(
			&BlockId::Number(0),
			SOURCE,
			to_top(
				TrustedCall::balance_transfer(
					tests::AccountId::from_h256(from_low_u64_to_be_h256(1)).into(),
					tests::AccountId::from_h256(from_low_u64_to_be_h256(2)).into(),
					5,
				),
				0,
			),
			shard,
		))
		.unwrap();
		let hash2 = block_on(pool.submit_one(
			&BlockId::Number(0),
			SOURCE,
			to_top(
				TrustedCall::balance_transfer(
					tests::AccountId::from_h256(from_low_u64_to_be_h256(1)).into(),
					tests::AccountId::from_h256(from_low_u64_to_be_h256(2)).into(),
					5,
				),
				1,
			),
			shard,
		))
		.unwrap();
		let hash3 = block_on(pool.submit_one(
			&BlockId::Number(0),
			SOURCE,
			to_top(
				TrustedCall::balance_transfer(
					tests::AccountId::from_h256(from_low_u64_to_be_h256(1)).into(),
					tests::AccountId::from_h256(from_low_u64_to_be_h256(2)).into(),
					5,
				),
				3,
			),
			shard,
		))
		.unwrap();
		// when
		pool.validated_pool.clear_stale(&BlockId::Number(5), shard).unwrap();

		// then
		assert_eq!(pool.validated_pool().ready(shard).count(), 0);
		assert_eq!(pool.validated_pool().status(shard).future, 0);
		assert_eq!(pool.validated_pool().status(shard).ready, 0);
		// make sure they are temporarily banned as well
		assert!(pool.validated_pool.rotator().is_banned(&hash1));
		assert!(pool.validated_pool.rotator().is_banned(&hash2));
		assert!(pool.validated_pool.rotator().is_banned(&hash3));
	}

	#[test]
	pub fn test_should_ban_mined_transactions() {
		// given
		let pool = test_pool();
		let shard = ShardIdentifier::default();
		let hash1 = block_on(pool.submit_one(
			&BlockId::Number(0),
			SOURCE,
			to_top(
				TrustedCall::balance_transfer(
					tests::AccountId::from_h256(from_low_u64_to_be_h256(1)).into(),
					tests::AccountId::from_h256(from_low_u64_to_be_h256(2)).into(),
					5,
				),
				0,
			),
			shard,
		))
		.unwrap();

		// when
		block_on(pool.prune_tags(&BlockId::Number(1), vec![vec![0]], vec![hash1], shard)).unwrap();

		// then
		assert!(pool.validated_pool.rotator().is_banned(&hash1));
	}

	#[test]
	#[ignore] // flaky, fails sometimes
	pub fn test_should_limit_futures() {
		// given
		let shard = ShardIdentifier::default();
		let limit = Limit { count: 100, total_bytes: 300 };
		let pool = Pool::new(
			Options { ready: limit.clone(), future: limit, ..Default::default() },
			TestApi::default().into(),
			Arc::new(TestRpcResponder::new()),
		);

		let hash1 = block_on(pool.submit_one(
			&BlockId::Number(0),
			SOURCE,
			to_top(
				TrustedCall::balance_transfer(
					tests::AccountId::from_h256(from_low_u64_to_be_h256(1)).into(),
					tests::AccountId::from_h256(from_low_u64_to_be_h256(2)).into(),
					5,
				),
				1,
			),
			shard,
		))
		.unwrap();
		assert_eq!(pool.validated_pool().status(shard).future, 1);

		// when
		let hash2 = block_on(pool.submit_one(
			&BlockId::Number(0),
			SOURCE,
			to_top(
				TrustedCall::balance_transfer(
					tests::AccountId::from_h256(from_low_u64_to_be_h256(2)).into(),
					tests::AccountId::from_h256(from_low_u64_to_be_h256(2)).into(),
					5,
				),
				10,
			),
			shard,
		))
		.unwrap();

		// then
		assert_eq!(pool.validated_pool().status(shard).future, 1);
		assert!(pool.validated_pool.rotator().is_banned(&hash1));
		assert!(!pool.validated_pool.rotator().is_banned(&hash2));
	}

	#[test]
	pub fn test_should_error_if_reject_immediately() {
		// given
		let shard = ShardIdentifier::default();
		let limit = Limit { count: 100, total_bytes: 10 };
		let pool = Pool::new(
			Options { ready: limit.clone(), future: limit, ..Default::default() },
			TestApi::default().into(),
			Arc::new(TestRpcResponder::new()),
		);

		// when
		block_on(pool.submit_one(
			&BlockId::Number(0),
			SOURCE,
			to_top(
				TrustedCall::balance_transfer(
					tests::AccountId::from_h256(from_low_u64_to_be_h256(1)).into(),
					tests::AccountId::from_h256(from_low_u64_to_be_h256(2)).into(),
					5,
				),
				1,
			),
			shard,
		))
		.unwrap_err();

		// then
		assert_eq!(pool.validated_pool().status(shard).ready, 0);
		assert_eq!(pool.validated_pool().status(shard).future, 0);
	}

	#[test]
	pub fn test_should_reject_transactions_with_no_provides() {
		// given
		let pool = test_pool();
		let shard = ShardIdentifier::default();

		// when
		let err = block_on(pool.submit_one(
			&BlockId::Number(0),
			SOURCE,
			to_top(
				TrustedCall::balance_transfer(
					tests::AccountId::from_h256(from_low_u64_to_be_h256(1)).into(),
					tests::AccountId::from_h256(from_low_u64_to_be_h256(2)).into(),
					5,
				),
				INVALID_NONCE,
			),
			shard,
		))
		.unwrap_err();

		// then
		assert_eq!(pool.validated_pool().status(shard).ready, 0);
		assert_eq!(pool.validated_pool().status(shard).future, 0);
		assert!(matches!(err, error::Error::NoTagsProvided));
	}
}
