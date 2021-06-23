use log::info;

use super::*;
use jsonrpsee::{
    types::{to_json_value, traits::Client}, ws_client::WsClientBuilder,
    };
use serde_json::Value as JsonValue;
use substratee_enclave_api::EnclaveResult;

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

pub fn ok_response(result: JsonValue, id: u32) -> String {
    format!(r#"{{"jsonrpc":"2.0","result":{},"id":{}}}"#, result, id)
}

struct TestEnclave;

impl EnclaveApi for TestEnclave {
    fn rpc(&self, request: Vec<u8>) -> EnclaveResult<Vec<u8>> {
        Ok(request)
    }
}

#[tokio::test]
async fn test_client_calls() {
    init();
    let addr = run_server("127.0.0.1:0", TestEnclave).await.unwrap();
    info!("ServerAddress: {:?}", addr);

    let url = format!("ws://{}", addr);
    let client = WsClientBuilder::default().build(&url).await.unwrap();
    let response: String = client
        .request(
            "sidechain_importBlock",
            vec![to_json_value(vec![1, 1, 2]).unwrap()].into(),
        )
        .await
        .unwrap();

    assert_eq!(response, ok_response(to_json_value([1, 1, 2]).unwrap(), 1));
}
