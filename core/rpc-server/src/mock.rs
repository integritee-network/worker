use parity_scale_codec::Encode;

use itp_enclave_api::{direct_request::DirectRequest, EnclaveResult};
use itp_types::RpcResponse;

pub struct TestEnclave;

impl DirectRequest for TestEnclave {
	fn rpc(&self, _request: Vec<u8>) -> EnclaveResult<Vec<u8>> {
		Ok(RpcResponse { jsonrpc: "mock_response".into(), result: "null".encode(), id: 1 }.encode())
	}
}
