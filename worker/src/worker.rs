use substratee_api_client_extensions::{SubstrateeRegistryApi, AccountApi, ChainApi};

use substratee_enclave_api::EnclaveApi;
use substratee_worker_rpc_server::ServerApi;


pub struct Worker<Config, NodeApi, Enclave, Server> {
	config: Config,
	node_api: NodeApi,
	enclave_api: Enclave,
	server: Server,
}

pub trait WorkerT<Config, NodeApi, Enclave, Server>
where
	NodeApi: SubstrateeRegistryApi + AccountApi + ChainApi,
	Enclave: EnclaveApi,
	Server: ServerApi,
{


}