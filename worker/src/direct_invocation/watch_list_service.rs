/*
    Copyright 2019 Supercomputing Systems AG

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

*/

use crate::direct_invocation::watching_client::WatchingClient;
use dashmap::DashMap;
use sp_core::H256 as Hash;

/// Trait to manage the watched list of direct invocation requests
pub trait WatchList: Send + Sync + 'static {
    type Client: WatchingClient;

    fn add_watching_client(&self, hash: Hash, client: Self::Client);

    fn remove_watching_client(&self, hash: &Hash);

    fn get_watching_client(&self, hash: &Hash) -> Option<Self::Client>;
}

#[derive(Clone)]
pub struct WatchListService<Client> {
    clients: DashMap<Hash, Client>,
}

impl<Client> WatchListService<Client> {
    pub fn new() -> Self {
        WatchListService {
            clients: DashMap::<Hash, Client>::new(),
        }
    }

    #[cfg(test)]
    pub fn number_of_elements(&self) -> usize {
        self.clients.len()
    }
}

impl<Client> WatchList for WatchListService<Client>
where
    Client: WatchingClient + Send + Sync + Clone + 'static,
{
    type Client = Client;

    fn add_watching_client(&self, hash: Hash, client: Client) {
        self.clients.insert(hash, client);
    }

    fn remove_watching_client(&self, hash: &Hash) {
        self.clients.remove(hash);
    }

    /// gets a copy (!!) of a client for a given hash
    fn get_watching_client(&self, hash: &Hash) -> Option<Client> {
        self.clients.get(hash).map(|c| (*c).clone())
    }
}
