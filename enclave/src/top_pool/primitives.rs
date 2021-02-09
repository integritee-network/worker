// File replacing substrate crate sp_transaction_pool::{error, PoolStatus};

extern crate alloc;
use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::{hash::Hash, pin::Pin};
use sgx_tstd::collections::HashMap;

use jsonrpc_core::futures::{channel, Future, Stream};
use sp_runtime::{
    generic::BlockId,
    traits::{Block as BlockT, Member, NumberFor},
    transaction_validity::{
        TransactionLongevity, TransactionPriority, TransactionSource, TransactionTag,
    },
};

use substratee_stf::{ShardIdentifier, TrustedOperation as StfTrustedOperation};

use crate::top_pool::error;

/// TrustedOperation pool status.
#[derive(Debug)]
pub struct PoolStatus {
    /// Number of operations in the ready queue.
    pub ready: usize,
    /// Sum of bytes of ready operation encodings.
    pub ready_bytes: usize,
    /// Number of operations in the future queue.
    pub future: usize,
    /// Sum of bytes of ready operation encodings.
    pub future_bytes: usize,
}

impl PoolStatus {
    /// Returns true if the are no operations in the pool.
    pub fn is_empty(&self) -> bool {
        self.ready == 0 && self.future == 0
    }
}

/// Possible operation status events.
///
/// This events are being emitted by `TrustedOperationPool` watchers,
/// which are also exposed over RPC.
///
/// The status events can be grouped based on their kinds as:
/// 1. Entering/Moving within the pool:
///		- `Future`
///		- `Ready`
/// 2. Inside `Ready` queue:
///		- `Broadcast`
/// 3. Leaving the pool:
///		- `InBlock`
///		- `Invalid`
///		- `Usurped`
///		- `Dropped`
///	4. Re-entering the pool:
///		- `Retracted`
///	5. Block finalized:
///		- `Finalized`
///		- `FinalityTimeout`
///
/// The events will always be received in the order described above, however
/// there might be cases where operations alternate between `Future` and `Ready`
/// pool, and are `Broadcast` in the meantime.
///
/// There is also only single event causing the operation to leave the pool.
/// I.e. only one of the listed ones should be triggered.
///
/// Note that there are conditions that may cause operations to reappear in the pool.
/// 1. Due to possible forks, the operation that ends up being in included
/// in one block, may later re-enter the pool or be marked as invalid.
/// 2. TrustedOperation `Dropped` at one point, may later re-enter the pool if some other
/// operations are removed.
/// 3. `Invalid` operation may become valid at some point in the future.
/// (Note that runtimes are encouraged to use `UnknownValidity` to inform the pool about
/// such case).
/// 4. `Retracted` operations might be included in some next block.
///
/// The stream is considered finished only when either `Finalized` or `FinalityTimeout`
/// event is triggered. You are however free to unsubscribe from notifications at any point.
/// The first one will be emitted when the block, in which operation was included gets
/// finalized. The `FinalityTimeout` event will be emitted when the block did not reach finality
/// within 512 blocks. This either indicates that finality is not available for your chain,
/// or that finality gadget is lagging behind. If you choose to wait for finality longer, you can
/// re-subscribe for a particular operation hash manually again.
#[derive(Debug, Clone, PartialEq)]
pub enum TrustedOperationStatus<Hash, BlockHash> {
    /// TrustedOperation is part of the future queue.
    Future,
    /// TrustedOperation is part of the ready queue.
    Ready,
    /// The operation has been broadcast to the given peers.
    Broadcast(Vec<String>),
    /// TrustedOperation has been included in block with given hash.
    InBlock(BlockHash),
    /// The block this operation was included in has been retracted.
    Retracted(BlockHash),
    /// Maximum number of finality watchers has been reached,
    /// old watchers are being removed.
    FinalityTimeout(BlockHash),
    /// TrustedOperation has been finalized by a finality-gadget, e.g GRANDPA
    Finalized(BlockHash),
    /// TrustedOperation has been replaced in the pool, by another operation
    /// that provides the same tags. (e.g. same (sender, nonce)).
    Usurped(Hash),
    /// TrustedOperation has been dropped from the pool because of the limit.
    Dropped,
    /// TrustedOperation is no longer valid in the current state.
    Invalid,
}

/// The stream of operation events.
pub type TrustedOperationStatusStream<Hash, BlockHash> =
    dyn Stream<Item = TrustedOperationStatus<Hash, BlockHash>> + Send + Unpin;

/// The import notification event stream.
pub type ImportNotificationStream<H> = channel::mpsc::Receiver<H>;

/// TrustedOperation hash type for a pool.
pub type TxHash<P> = <P as TrustedOperationPool>::Hash;
/// Block hash type for a pool.
pub type BlockHash<P> = <<P as TrustedOperationPool>::Block as BlockT>::Hash;
/// Type of operations event stream for a pool.
pub type TrustedOperationStatusStreamFor<P> = TrustedOperationStatusStream<TxHash<P>, BlockHash<P>>;


/// Typical future type used in operation pool api.
pub type PoolFuture<T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send>>;

/// In-pool operation interface.
///
/// The pool is container of operations that are implementing this trait.
/// See `sp_runtime::ValidTransaction` for details about every field.
pub trait InPoolOperation {
    /// TrustedOperation type.
    type TrustedOperation;
    /// TrustedOperation hash type.
    type Hash;

    /// Get the reference to the operation data.
    fn data(&self) -> &Self::TrustedOperation;
    /// Get hash of the operation.
    fn hash(&self) -> &Self::Hash;
    /// Get priority of the operation.
    fn priority(&self) -> &TransactionPriority;
    /// Get longevity of the operation.
    fn longevity(&self) -> &TransactionLongevity;
    /// Get operation dependencies.
    fn requires(&self) -> &[TransactionTag];
    /// Get tags that operation provides.
    fn provides(&self) -> &[TransactionTag];
    /// Return a flag indicating if the operation should be propagated to other peers.
    fn is_propagable(&self) -> bool;
}

/// TrustedOperation pool interface.
pub trait TrustedOperationPool: Send + Sync {
    /// Block type.
    type Block: BlockT;
    /// TrustedOperation hash type.
    type Hash: Hash + Eq + Member;
    /// In-pool operation type.
    type InPoolOperation: InPoolOperation<TrustedOperation = StfTrustedOperation, Hash = TxHash<Self>>;
    /// Error type.
    type Error: From<error::Error> + error::IntoPoolError;

    // *** RPC

    /// Returns a future that imports a bunch of unverified operations to the pool.
    fn submit_at(
        &self,
        at: &BlockId<Self::Block>,
        source: TransactionSource,
        xts: Vec<StfTrustedOperation>,
        shard: ShardIdentifier,
    ) -> PoolFuture<Vec<Result<TxHash<Self>, Self::Error>>, Self::Error>;

    /// Returns a future that imports one unverified operation to the pool.
    fn submit_one(
        &self,
        at: &BlockId<Self::Block>,
        source: TransactionSource,
        xt: StfTrustedOperation,
        shard: ShardIdentifier,
    ) -> PoolFuture<TxHash<Self>, Self::Error>;

    /// Returns a future that import a single operation and starts to watch their progress in the pool.
    fn submit_and_watch(
        &self,
        at: &BlockId<Self::Block>,
        source: TransactionSource,
        xt: StfTrustedOperation,
        shard: ShardIdentifier,
    ) -> PoolFuture<TxHash<Self>, Self::Error>;

    // *** Block production / Networking
    /// Get an iterator for ready operations ordered by priority.
    ///
    /// Guarantees to return only when operation pool got updated at `at` block.
    /// Guarantees to return immediately when `None` is passed.
    fn ready_at(
        &self,
        at: NumberFor<Self::Block>,
        shard: ShardIdentifier,
    ) -> Pin<
        Box<
            dyn Future<Output = Box<dyn Iterator<Item = Arc<Self::InPoolOperation>> + Send>>
                + Send,
        >,
    >;

    /// Get an iterator for ready operations ordered by priority.
    fn ready(
        &self,
        shard: ShardIdentifier,
    ) -> Box<dyn Iterator<Item = Arc<Self::InPoolOperation>> + Send>;

    /// Get an iterator over all shards.
    fn shards(&self) -> Vec<ShardIdentifier>;

    // *** Block production
    /// Remove operations identified by given hashes (and dependent operations) from the pool.
    fn remove_invalid(
        &self,
        hashes: &[TxHash<Self>],
        shard: ShardIdentifier,
        inblock: bool,
    ) -> Vec<Arc<Self::InPoolOperation>>;

    // *** logging
    /// Returns pool status.
    fn status(&self, shard: ShardIdentifier) -> PoolStatus;

    // *** logging / RPC / networking
    /// Return an event stream of operations imported to the pool.
    fn import_notification_stream(&self) -> ImportNotificationStream<TxHash<Self>>;

    // *** networking
    /// Notify the pool about operations broadcast.
    fn on_broadcasted(&self, propagations: HashMap<TxHash<Self>, Vec<String>>);

    /// Returns operation hash
    fn hash_of(&self, xt: &StfTrustedOperation) -> TxHash<Self>;

    /// Return specific ready operation by hash, if there is one.
    fn ready_transaction(
        &self,
        hash: &TxHash<Self>,
        shard: ShardIdentifier,
    ) -> Option<Arc<Self::InPoolOperation>>;
}

/*
/// Events that the operation pool listens for.
pub enum ChainEvent<B: BlockT> {
    /// New best block have been added to the chain
    NewBestBlock {
        /// Hash of the block.
        hash: B::Hash,
        /// Tree route from old best to new best parent that was calculated on import.
        ///
        /// If `None`, no re-org happened on import.
        tree_route: Option<Arc<sp_blockchain::TreeRoute<B>>>,
    },
    /// An existing block has been finalized.
    Finalized {
        /// Hash of just finalized block
        hash: B::Hash,
    },
}

/// Trait for operation pool maintenance.
pub trait MaintainedTrustedOperationPool: TrustedOperationPool {
    /// Perform maintenance
    fn maintain(&self, event: ChainEvent<Self::Block>) -> Pin<Box<dyn Future<Output=()> + Send>>;
}*/

/// TrustedOperation pool interface for submitting local operations that exposes a
/// blocking interface for submission.
pub trait LocalTrustedOperationPool: Send + Sync {
    /// Block type.
    type Block: BlockT;
    /// TrustedOperation hash type.
    type Hash: Hash + Eq + Member;
    /// Error type.
    type Error: From<error::Error> + error::IntoPoolError;

    /// Submits the given local unverified operation to the pool blocking the
    /// current thread for any necessary pre-verification.
    /// NOTE: It MUST NOT be used for operations that originate from the
    /// network or RPC, since the validation is performed with
    /// `TransactionSource::Local`.
    fn submit_local(
        &self,
        at: &BlockId<Self::Block>,
        xt: StfTrustedOperation,
    ) -> Result<Self::Hash, Self::Error>;
}
/*
/// An abstraction for operation pool.
///
/// This trait is used by offchain calls to be able to submit operations.
/// The main use case is for offchain workers, to feed back the results of computations,
/// but since the operation pool access is a separate `ExternalitiesExtension` it can
/// be also used in context of other offchain calls. For one may generate and submit
/// a operation for some misbehavior reports (say equivocation).
pub trait OffchainSubmitTransaction<Block: BlockT>: Send + Sync {
    /// Submit operation.
    ///
    /// The operation will end up in the pool and be propagated to others.
    fn submit_at(
        &self,
        at: &BlockId<Block>,
        extrinsic: Block::Extrinsic,
    ) -> Result<(), ()>;
}

impl<TPool: LocalTrustedOperationPool> OffchainSubmitTransaction<TPool::Block> for TPool {
    fn submit_at(
        &self,
        at: &BlockId<TPool::Block>,
        extrinsic: <TPool::Block as BlockT>::Extrinsic,
    ) -> Result<(), ()> {
        log::debug!(
            target: "txpool",
            "(offchain call) Submitting a operation to the pool: {:?}",
            extrinsic
        );

        let result = self.submit_local(&at, extrinsic);

        result.map(|_| ()).map_err(|e| {
            log::warn!(
                target: "txpool",
                "(offchain call) Error submitting a operation to the pool: {:?}",
                e
            )
        })
    }
}
*/
