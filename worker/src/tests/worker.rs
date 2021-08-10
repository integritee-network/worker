use lazy_static::lazy_static;
use parking_lot::RwLock;
use substratee_api_client_extensions::PalletTeerexApi;

use crate::{
	config::Config,
	tests::{
		commons::local_worker_config,
		mock::{enclaves, TestNodeApi, W2_URL},
	},
	worker::Worker as WorkerGen,
};
use std::sync::Arc;

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
			Arc::new(()),
			(),
		));
	}

	let w = WORKER.read();
	// call some random function to see how the worker needs to be called.
	assert_eq!(w.as_ref().unwrap().node_api().all_enclaves().unwrap(), enclaves())
}
