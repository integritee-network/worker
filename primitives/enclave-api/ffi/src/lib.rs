///! FFI's that call into the enclave. These functions need to be added to the
/// enclave edl file and be implemented within the enclave.

use sgx_types::{sgx_enclave_id_t, sgx_status_t};

extern "C" {
	pub fn call_rpc_methods(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		request: *const u8,
		request_len: u32,
		response: *mut u8,
		response_len: u32,
	) -> sgx_status_t;

	pub fn mock_register_enclave_xt(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		genesis_hash: *const u8,
		genesis_hash_size: u32,
		nonce: *const u32,
		w_url: *const u8,
		w_url_size: u32,
		unchecked_extrinsic: *mut u8,
		unchecked_extrinsic_size: u32,
	) -> sgx_status_t;
}