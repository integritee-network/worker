use log::info;

use super::*;
use jsonrpsee::{
    types::{to_json_value, traits::Client},
    ws_client::WsClientBuilder,
};
use parity_scale_codec::Decode;

use mock::{test_sidechain_block, TestEnclave};
use substratee_worker_primitives::RpcResponse;

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

#[tokio::test]
async fn test_client_calls() {
    init();
    let addr = run_server("127.0.0.1:0", Arc::new(TestEnclave))
        .await
        .unwrap();
    info!("ServerAddress: {:?}", addr);

    let url = format!("ws://{}", addr);
    let client = WsClientBuilder::default().build(&url).await.unwrap();
    let response: Vec<u8> = client
        .request(
            "sidechain_importBlock",
            vec![to_json_value(vec![test_sidechain_block()]).unwrap()].into(),
        )
        .await
        .unwrap();

    assert!(RpcResponse::decode(&mut response.as_slice()).is_ok());
}
