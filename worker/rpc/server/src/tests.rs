use log::info;

use super::*;
use jsonrpsee::{
    types::{to_json_value, traits::Client},
    ws_client::WsClientBuilder,
};
use substratee_enclave_api::EnclaveResult;

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
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
    let response: Vec<u8> = client
        .request(
            "sidechain_importBlock",
            vec![to_json_value(vec![1, 1, 2]).unwrap()].into(),
        )
        .await
        .unwrap();

    assert_eq!(response, vec![1, 1, 2]);
}
