///! FFI's that call into the enclave. These functions need to be added to the
/// enclave edl file and be implemented within the enclave.
use sgx_types::{
	c_int, sgx_enclave_id_t, sgx_ql_qve_collateral_t, sgx_quote_sign_type_t, sgx_status_t,
	sgx_target_info_t,
};

extern "C" {

	pub fn generate_dcap_ra_extrinsic_from_quote(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		w_url: *const u8,
		w_url_size: u32,
		quote: *const u8,
		quote_size: u32,
		unchecked_extrinsic: *mut u8,
		unchecked_extrinsic_size: u32,
	) -> sgx_status_t;

	pub fn init(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		mu_ra_addr: *const u8,
		mu_ra_addr_size: u32,
		untrusted_worker_addr: *const u8,
		untrusted_worker_addr_size: u32,
		encoded_base_dir_str: *const u8,
		encoded_base_dir_size: u32,
	) -> sgx_status_t;

	pub fn init_enclave_sidechain_components(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
	) -> sgx_status_t;

	pub fn init_direct_invocation_server(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		server_addr: *const u8,
		server_addr_size: u32,
	) -> sgx_status_t;

	pub fn init_parentchain_components(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		params: *const u8,
		params_size: usize,
		latest_header: *mut u8,
		latest_header_size: usize,
	) -> sgx_status_t;

	pub fn init_shard(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		shard: *const u8,
		shard_size: u32,
	) -> sgx_status_t;

	pub fn trigger_parentchain_block_import(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
	) -> sgx_status_t;

	pub fn execute_trusted_calls(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;

	pub fn sync_parentchain(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		blocks: *const u8,
		blocks_size: usize,
		events: *const u8,
		events_size: usize,
		events_proofs: *const u8,
		events_proofs_size: usize,
		nonce: *const u32,
	) -> sgx_status_t;

	pub fn set_nonce(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		nonce: *const u32,
	) -> sgx_status_t;

	pub fn set_node_metadata(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		node_metadata: *const u8,
		node_metadata_size: u32,
	) -> sgx_status_t;

	pub fn get_rsa_encryption_pubkey(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		pubkey: *mut u8,
		pubkey_size: u32,
	) -> sgx_status_t;

	pub fn get_ecc_signing_pubkey(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		pubkey: *mut u8,
		pubkey_size: u32,
	) -> sgx_status_t;

	pub fn get_mrenclave(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		mrenclave: *mut u8,
		mrenclave_size: u32,
	) -> sgx_status_t;

	pub fn generate_ias_ra_extrinsic(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		w_url: *const u8,
		w_url_size: u32,
		unchecked_extrinsic: *mut u8,
		unchecked_extrinsic_size: u32,
		skip_ra: c_int,
	) -> sgx_status_t;

	pub fn generate_dcap_ra_extrinsic(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		w_url: *const u8,
		w_url_size: u32,
		unchecked_extrinsic: *mut u8,
		unchecked_extrinsic_size: u32,
		skip_ra: c_int,
		quoting_enclave_target_info: Option<&sgx_target_info_t>,
		quote_size: Option<&u32>,
	) -> sgx_status_t;

	pub fn generate_dcap_ra_quote(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		skip_ra: c_int,
		quoting_enclave_target_info: &sgx_target_info_t,
		quote_size: u32,
		dcap_quote_p: *mut u8,
		dcap_quote_size: u32,
	) -> sgx_status_t;

	pub fn generate_register_quoting_enclave_extrinsic(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		collateral: *const sgx_ql_qve_collateral_t,
		unchecked_extrinsic: *mut u8,
		unchecked_extrinsic_size: u32,
	) -> sgx_status_t;

	pub fn generate_register_tcb_info_extrinsic(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		collateral: *const sgx_ql_qve_collateral_t,
		unchecked_extrinsic: *mut u8,
		unchecked_extrinsic_size: u32,
	) -> sgx_status_t;

	pub fn dump_ias_ra_cert_to_disk(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
	) -> sgx_status_t;

	pub fn dump_dcap_ra_cert_to_disk(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		quoting_enclave_target_info: &sgx_target_info_t,
		quote_size: u32,
	) -> sgx_status_t;

	pub fn dump_dcap_collateral_to_disk(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		collateral: *const sgx_ql_qve_collateral_t,
	) -> sgx_status_t;

	pub fn test_main_entrance(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;

	pub fn call_rpc_methods(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		request: *const u8,
		request_len: u32,
		response: *mut u8,
		response_len: u32,
	) -> sgx_status_t;

	pub fn update_market_data_xt(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		crypto_currency: *const u8,
		crypto_currency_size: u32,
		fiat_currency: *const u8,
		fiat_currency_size: u32,
		unchecked_extrinsic: *mut u8,
		unchecked_extrinsic_size: u32,
	) -> sgx_status_t;

	pub fn update_weather_data_xt(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		weather_info_longitude: *const u8,
		weather_info_longitude_size: u32,
		weather_info_latitude: *const u8,
		weather_info_latitude_size: u32,
		unchecked_extrinsic: *mut u8,
		unchecked_extrinsic_size: u32,
	) -> sgx_status_t;

	pub fn run_state_provisioning_server(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		socket_fd: c_int,
		sign_type: sgx_quote_sign_type_t,
		quoting_enclave_target_info: Option<&sgx_target_info_t>,
		quote_size: Option<&u32>,
		skip_ra: c_int,
	) -> sgx_status_t;

	pub fn request_state_provisioning(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		socket_fd: c_int,
		sign_type: sgx_quote_sign_type_t,
		quoting_enclave_target_info: Option<&sgx_target_info_t>,
		quote_size: Option<&u32>,
		shard: *const u8,
		shard_size: u32,
		skip_ra: c_int,
	) -> sgx_status_t;

}
