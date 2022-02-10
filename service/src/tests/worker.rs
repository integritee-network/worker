use itp_node_api_extensions::PalletTeerexApi;
use lazy_static::lazy_static;
use parking_lot::RwLock;

use crate::{
	config::Config,
	tests::{
		commons::local_worker_config,
		mock::{enclaves, TestNodeApi, W2_URL},
	},
	worker::Worker as WorkerGen,
};
use std::sync::Arc;

type TestWorker = WorkerGen<Config, TestNodeApi, ()>;

lazy_static! {
	static ref WORKER: RwLock<Option<TestWorker>> = RwLock::new(None);
}

#[test]
fn worker_rw_lock_works() {
	{
		let mut w = WORKER.write();
		*w = Some(TestWorker::new(
			local_worker_config(W2_URL.into(), "10".to_string(), "20".to_string()),
			TestNodeApi,
			Arc::new(()),
			Vec::new(),
		));
	}

	let w = WORKER.read();
	// call some random function to see how the worker needs to be called.
	assert_eq!(w.as_ref().unwrap().node_api().all_enclaves(None).unwrap(), enclaves())
}
