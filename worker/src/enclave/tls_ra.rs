/*
    Copyright 2019 Supercomputing Systems AG

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
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;

use sgx_types::*;

use log::*;

extern "C" {
    fn run_key_provisioning_server(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        socket_fd: c_int,
        sign_type: sgx_quote_sign_type_t,
    ) -> sgx_status_t;
    fn request_key_provisioning(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        socket_fd: c_int,
        sign_type: sgx_quote_sign_type_t,
    ) -> sgx_status_t;
}

pub fn enclave_run_key_provisioning_server(
    eid: sgx_enclave_id_t,
    sign_type: sgx_quote_sign_type_t,
    addr: &str,
) {
    info!("Starting MU-RA-Server on: {}", addr);
    let listener = TcpListener::bind(addr).unwrap();
    loop {
        match listener.accept() {
            Ok((socket, addr)) => {
                info!(
                    "[MU-RA-Server] a worker at {} is requesting key provisiong",
                    addr
                );
                let mut retval = sgx_status_t::SGX_SUCCESS;
                let result = unsafe {
                    run_key_provisioning_server(eid, &mut retval, socket.as_raw_fd(), sign_type)
                };
                match result {
                    sgx_status_t::SGX_SUCCESS => {
                        debug!("[MU-RA-Server] ECALL success!");
                    }
                    _ => {
                        error!("[MU-RA-Server] ECALL Enclave Failed {}!", result.as_str());
                    }
                }
            }
            Err(e) => error!("couldn't get client: {:?}", e),
        }
    }
}

pub fn enclave_request_key_provisioning(
    eid: sgx_enclave_id_t,
    sign_type: sgx_quote_sign_type_t,
    addr: &str,
) -> SgxResult<()> {
    info!("[MU-RA-Client] Requesting key provisioning from {}", addr);
    let socket = TcpStream::connect(addr).unwrap();
    let mut status = sgx_status_t::SGX_SUCCESS;

    let result =
        unsafe { request_key_provisioning(eid, &mut status, socket.as_raw_fd(), sign_type) };
    if status != sgx_status_t::SGX_SUCCESS {
        return Err(status);
    }
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }
    Ok(())
}
