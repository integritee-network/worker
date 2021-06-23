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
}