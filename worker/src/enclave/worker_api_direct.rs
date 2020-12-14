// TODO: Adapt this copyright according to licencse

// This file is part of Substrate.

// Copyright (C) 2017-2020 Parity Technologies (UK) Ltd.
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

//! Substrate block-author/full-node API.

extern crate json_rpc;
use json_rpc::{Server, Json, Error};

extern "C" {
    fn start_rpc_server(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        socket_fd: c_int,
        sign_type: sgx_quote_sign_type_t,
        api: API,
    ) -> sgx_status_t;
}

pub fn enclave_start_worker_api_direct(
	eid: sgx_enclave_id_t,
    sign_type: sgx_quote_sign_type_t,
    addr: &str,
) {
	info!("Starting worker API on: {}", addr);
    let listener = TcpListener::bind(addr).unwrap();
    loop {
        match listener.accept() {
            Ok((socket, addr)) => {
                info!(
                    "[worker-API-direct] a worker at {} is requesting an rpc method",
                    addr
                );
                let mut retval = sgx_status_t::SGX_SUCCESS;
                let result = unsafe {
                    start_rpc_server(eid, &mut retval, socket.as_raw_fd(), sign_type)
                };
                match result {
                    sgx_status_t::SGX_SUCCESS => {
                        debug!("[worker-API-direct] ECALL success!");
                    }
                    _ => {
                        error!("[worker-API-direct] ECALL Enclave Failed {}!", result.as_str());
                    }
                }
            }
            Err(e) => error!("couldn't get client: {:?}", e),
        }
    }



}
