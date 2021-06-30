use lazy_static::lazy_static;
use parking_lot::RwLock;
use substratee_api_client_extensions::SubstrateeRegistryApi;

use crate::config::Config;
use crate::tests::commons::local_worker_config;
use crate::tests::mock::{enclaves, TestNodeApi, W2_URL};
use crate::worker::Worker as WorkerGen;

type TestWorker = WorkerGen<Config, TestNodeApi, (), ()>;

lazy_static! {
    static ref WORKER: RwLock<Option<TestWorker>> = RwLock::new(None);
}

#[test]
fn worker_rw_lock_works() {
    {
        let mut w = WORKER.write();
        *w = Some(TestWorker::new(
            local_worker_config(W2_URL.into()),
            TestNodeApi,
            (),
            (),
        ));
    }

    let w = WORKER.read();
    // call some random function to see how the worker needs to be called.
    assert_eq!(
        w.as_ref().unwrap().node_api().all_enclaves().unwrap(),
        enclaves()
    )
}
