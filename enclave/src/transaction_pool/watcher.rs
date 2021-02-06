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

//! Extrinsics status updates.

extern crate alloc;
use alloc::{string::String, vec::Vec};

use codec::Encode;
use sp_runtime::traits;

use sgx_tstd::hash;

//use crate::transaction_pool::primitives::TransactionStatus
use crate::rpc::worker_api_direct;
use substratee_worker_primitives::TransactionStatus;

/// Extrinsic watcher.
///
/// Represents a stream of status updates for particular extrinsic.
#[derive(Debug)]
pub struct Watcher<H> {
    //receiver: TracingUnboundedReceiver<TransactionStatus<H, BH>>,
    hash: H,
    is_in_block: bool,
}

impl<H: hash::Hash + Encode + traits::Member> Watcher<H> {
    /// Returns the transaction hash.
    pub fn hash(&self) -> &H {
        &self.hash
    }

    pub fn new_watcher(hash: H) -> Watcher<H> {
        //let (sender, receiver) = tracing_unbounded("mpsc_txpool_watcher");
        //self.receivers.push(sender);
        Watcher {
            hash,
            is_in_block: false,
        }
    }

    /// Transaction became ready.
    pub fn ready(&mut self) {
        self.send(TransactionStatus::Ready)
    }

    /// Transaction was moved to future.
    pub fn future(&mut self) {
        self.send(TransactionStatus::Future)
    }

    /// Some state change (perhaps another extrinsic was included) rendered this extrinsic invalid.
    pub fn usurped(&mut self) {
        //self.send(TransactionStatus::Usurped(hash));
        self.send(TransactionStatus::Usurped);
        self.is_in_block = true;
    }

    /// Extrinsic has been included in block with given hash.
    pub fn in_block(&mut self) {
        //self.send(TransactionStatus::InBlock(hash));
        self.send(TransactionStatus::InBlock);
        self.is_in_block = true;
    }

    /// Extrinsic has been finalized by a finality gadget.
    pub fn finalized(&mut self) {
        //self.send(TransactionStatus::Finalized(hash));
        self.send(TransactionStatus::Finalized);
        self.is_in_block = true;
    }

    /// The block this extrinsic was included in has been retracted
    pub fn finality_timeout(&mut self) {
        //self.send(TransactionStatus::FinalityTimeout(hash));
        self.send(TransactionStatus::FinalityTimeout);
        self.is_in_block = true;
    }

    /// The block this extrinsic was included in has been retracted
    pub fn retracted(&mut self) {
        //self.send(TransactionStatus::Retracted(hash));
        self.send(TransactionStatus::Retracted);
    }

    /// Extrinsic has been marked as invalid by the block builder.
    pub fn invalid(&mut self) {
        self.send(TransactionStatus::Invalid);
        // we mark as finalized as there are no more notifications
        self.is_in_block = true;
    }

    /// Transaction has been dropped from the pool because of the limit.
    pub fn dropped(&mut self) {
        self.send(TransactionStatus::Dropped);
        self.is_in_block = true;
    }

    /// The extrinsic has been broadcast to the given peers.
    pub fn broadcast(&mut self, _peers: Vec<String>) {
        //self.send(TransactionStatus::Broadcast(peers))
        self.send(TransactionStatus::Broadcast)
    }

    /// Returns true if the are no more listeners for this extrinsic or it was finalized.
    pub fn is_done(&self) -> bool {
        self.is_in_block // || self.receivers.is_empty()
    }

    fn send(&mut self, status: TransactionStatus) {
        worker_api_direct::update_status_event(self.hash(), status).unwrap();
    }
}

/*  /// Sender part of the watcher. Exposed only for testing purposes.
#[derive(Debug)]
pub struct Sender<H, BH> {
    //receivers: Vec<TracingUnboundedSender<TransactionStatus<H, BH>>>,
    //receivers: Vec<H>,
    is_in_block: bool,
}
 */
/* impl<H> Default for Watcher<H> {
    fn default() -> Self {
        Watcher {
            //receivers: Default::default(),
            hash: ,
            is_in_block: false,
        }
    }
}  */

/* impl<H: Clone, BH: Clone> Sender<H, BH> {
    /// Add a new watcher to this sender object.

} */
