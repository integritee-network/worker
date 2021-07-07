/*
    Copyright 2019 Supercomputing Systems AG
    Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.

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

use crate::node_api_factory::NodeApiFactory;
use crate::ocall_bridge::bridge_api::{OCallBridgeError, OCallBridgeResult, WorkerOnChainOCall};
use crate::utils::hex_encode;
use codec::Decode;
use frame_support::ensure;
use log::*;
use sgx_types::sgx_status_t;
use sp_core::Pair;
use std::slice;
use std::sync::mpsc::channel;
use substrate_api_client::{Api, XtStatus};

pub struct WorkerOnChainOCallImpl<P, F>
where
    P: Pair,
    F: NodeApiFactory<P>,
{
    node_api_factory: F,
}

impl<P, F> WorkerOnChainOCallImpl<P, F>
where
    P: Pair,
    F: NodeApiFactory<P>,
{
    pub fn new(node_api_factory: F) -> Self {
        WorkerOnChainOCallImpl { node_api_factory }
    }
}

impl<P, F> WorkerOnChainOCall for WorkerOnChainOCallImpl<P, F>
where
    P: Pair,
    F: NodeApiFactory<P>,
{
    fn worker_request(&self, request: Vec<u8>) -> OCallBridgeResult<Vec<u8>> {
        todo!()
    }

    fn send_block_and_confirmation(
        &self,
        confirmations: &mut [u8],
        signed_blocks: &mut [u8],
    ) -> OCallBridgeResult<()> {
        debug!("    Entering ocall_send_block_and_confirmation");

        // TODO: improve error handling, using a mut status is not good design?
        let mut status: OCallBridgeResult<()> = Ok(());
        let api = self.node_api_factory.create_api();

        // send confirmations to layer one
        let confirmation_calls: Vec<Vec<u8>> = match Decode::decode(confirmations) {
            Ok(calls) => calls,
            Err(_) => {
                status = Err(OCallBridgeError::SendBlockAndConfirmation(
                    "Could not decode confirmation calls".to_string(),
                ));
                vec![vec![]]
            }
        };

        if !confirmation_calls.is_empty() {
            println!(
                "Enclave wants to send {} extrinsics",
                confirmation_calls.len()
            );
            for call in confirmation_calls.into_iter() {
                api.send_extrinsic(hex_encode(call), XtStatus::Ready)
                    .unwrap();
            }
            // await next block to avoid #37
            let (events_in, events_out) = channel();
            api.subscribe_events(events_in).unwrap();
            let _ = events_out.recv().unwrap();
            let _ = events_out.recv().unwrap();
            // FIXME: we should unsubscribe here or the thread will throw a SendError because the channel is destroyed
        }

        // handle blocks
        let signed_blocks: Vec<SignedSidechainBlock> = match Decode::decode(signed_blocks) {
            Ok(blocks) => blocks,
            Err(_) => {
                status = Err(OCallBridgeError::SendBlockAndConfirmation(
                    "Could not decode confirmation calls".to_string(),
                ));
                vec![]
            }
        };

        println! {"Received blocks: {:?}", signed_blocks};

        let w = WORKER.read();

        // make it sync, as sgx ffi does not support async/await
        let handle = TOKIO_HANDLE.lock().unwrap().as_ref().unwrap().clone();
        if let Err(e) = handle.block_on(w.as_ref().unwrap().gossip_blocks(signed_blocks)) {
            error!("Error gossiping blocks: {:?}", e);
            // Fixme: returning an error here results in a `HeaderAncestryMismatch` error.
            // status = sgx_status_t::SGX_ERROR_UNEXPECTED;
        };
        // TODO: M8.3: Store blocks

        status
    }
}
