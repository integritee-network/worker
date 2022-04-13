/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

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

#[cfg(feature = "sgx")]
use std::sync::SgxRwLock as RwLock;

#[cfg(feature = "std")]
use std::sync::RwLock;

use crate::{
	connection_id_generator::ConnectionId,
	error::{WebSocketError, WebSocketError::LockPoisoning},
	WebSocketConnection, WebSocketResult,
};
use log::error;
use std::{
	collections::{HashMap, VecDeque},
	fmt::Debug,
};

pub trait AddNewConnection<Connection> {
	fn add_new_connection(&self, connection: Connection) -> WebSocketResult<()>;
}

pub trait ConnectionRepositoryControl<Connection> {
	fn move_new_connections_to_active(&self) -> WebSocketResult<()>;

	fn process_active_connections<F, R, E>(
		&self,
		connection_processor: F,
	) -> WebSocketResult<Vec<R>>
	where
		F: Fn(&mut Connection) -> Result<R, E>,
		E: Debug;

	fn execute_on_connection<F, R>(
		&self,
		connection_id: ConnectionId,
		execute_fn: F,
	) -> WebSocketResult<R>
	where
		F: FnOnce(&mut Connection) -> WebSocketResult<R>;

	fn remove_connections(&self, connections: &[ConnectionId]) -> WebSocketResult<()>;
}

/// Repository to manage websocket connections in a thread-safe manner.
///
/// Tracks new connections in a separate collection, so we can concurrently
/// process the active connections and add new ones.
#[derive(Default)]
pub struct ConnectionRepository<Connection>
where
	Connection: WebSocketConnection,
{
	active_connections: RwLock<HashMap<ConnectionId, Connection>>,
	new_connections: RwLock<VecDeque<Connection>>,
}

impl<Connection> ConnectionRepository<Connection> where Connection: WebSocketConnection {}

impl<Connection> AddNewConnection<Connection> for ConnectionRepository<Connection>
where
	Connection: WebSocketConnection,
{
	fn add_new_connection(&self, connection: Connection) -> WebSocketResult<()> {
		let mut new_connections_lock = self.new_connections.write().map_err(|_| LockPoisoning)?;
		new_connections_lock.push_back(connection);
		Ok(())
	}
}

impl<Connection> ConnectionRepositoryControl<Connection> for ConnectionRepository<Connection>
where
	Connection: WebSocketConnection,
{
	fn move_new_connections_to_active(&self) -> WebSocketResult<()> {
		let mut new_connections_lock = self.new_connections.write().map_err(|_| LockPoisoning)?;
		let mut active_connections_lock =
			self.active_connections.write().map_err(|_| LockPoisoning)?;

		let drained_connections = new_connections_lock.drain(..);

		drained_connections.into_iter().for_each(|c| {
			let _ = active_connections_lock.insert(c.id(), c);
		});
		Ok(())
	}

	fn process_active_connections<F, R, E>(
		&self,
		connection_processor: F,
	) -> WebSocketResult<Vec<R>>
	where
		F: Fn(&mut Connection) -> Result<R, E>,
		E: Debug,
	{
		let mut active_connections_lock =
			self.active_connections.write().map_err(|_| LockPoisoning)?;

		let results: Vec<R> = active_connections_lock
			.values_mut()
			.flat_map(|active_connection| match (connection_processor)(active_connection) {
				Ok(r) => Some(r),
				Err(e) => {
					error!("Failed to process web socket connection: {:?}", e);
					None
				},
			})
			.collect();

		Ok(results)
	}

	fn execute_on_connection<F, R>(
		&self,
		connection_id: ConnectionId,
		execute_fn: F,
	) -> WebSocketResult<R>
	where
		F: FnOnce(&mut Connection) -> WebSocketResult<R>,
	{
		let mut active_connections_lock =
			self.active_connections.write().map_err(|_| LockPoisoning)?;

		let connection = active_connections_lock
			.get_mut(&connection_id)
			.ok_or_else(|| WebSocketError::InvalidConnection(connection_id))?;

		(execute_fn)(connection)
	}

	fn remove_connections(&self, connection_ids: &[ConnectionId]) -> WebSocketResult<()> {
		let mut active_connections_lock =
			self.active_connections.write().map_err(|_| LockPoisoning)?;

		for connection_id in connection_ids {
			let _ = active_connections_lock.remove(connection_id);
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		connection_id_generator::ConnectionId, error::WebSocketError,
		test::mocks::web_socket_connection_mock::WebSocketConnectionMock,
	};

	type TestConnectionRepository = ConnectionRepository<WebSocketConnectionMock>;

	#[test]
	fn moving_new_connections_works() {
		let repository = TestConnectionRepository::default();

		assert!(repository.active_connections.read().unwrap().is_empty());

		repository.add_new_connection(WebSocketConnectionMock::new(1)).unwrap();
		repository.add_new_connection(WebSocketConnectionMock::new(2)).unwrap();

		repository.move_new_connections_to_active().unwrap();

		assert_eq!(2, repository.active_connections.read().unwrap().len());
	}

	#[test]
	fn processing_active_connections_works() {
		let connection_ids: Vec<ConnectionId> = vec![1, 2, 3];
		let repository = given_repo_with_active_connections(connection_ids.as_slice());

		let connections_processed =
			repository.process_active_connections::<_, _, String>(|c| Ok(c.id())).unwrap();

		assert_eq!(connection_ids.len(), connections_processed.len());
	}

	#[test]
	fn processing_failure_in_a_single_connection_does_not_abort_others() {
		let connection_ids: Vec<ConnectionId> = vec![1, 2, 3];
		let repository = given_repo_with_active_connections(connection_ids.as_slice());

		let connections_processed = repository
			.process_active_connections(|c| match c.id() {
				1 => Err(WebSocketError::LockPoisoning),
				_ => Ok(c.id()),
			})
			.unwrap();

		assert_eq!(2, connections_processed.len());
	}

	#[test]
	fn removing_active_connections_works() {
		let connection_ids: Vec<ConnectionId> = vec![1, 2, 3, 4, 5, 6];
		let repository = given_repo_with_active_connections(connection_ids.as_slice());

		repository.remove_connections(&[2, 4, 6, 8, 10]).unwrap();

		assert_eq!(3, repository.active_connections.read().unwrap().len());
	}

	#[test]
	fn execute_on_connection_works() {
		let connection_ids: Vec<ConnectionId> = vec![1, 2, 3, 4, 5, 6];
		let repository = given_repo_with_active_connections(connection_ids.as_slice());

		assert!(repository.execute_on_connection(7, |_c| { Ok(()) }).is_err());

		let connection_id = repository.execute_on_connection(2, |c| Ok(c.id())).unwrap();
		assert_eq!(2, connection_id);
	}

	fn given_repo_with_active_connections(
		connection_ids: &[ConnectionId],
	) -> TestConnectionRepository {
		let repository = TestConnectionRepository::default();

		for connection_id in connection_ids {
			repository
				.add_new_connection(WebSocketConnectionMock::new(*connection_id))
				.unwrap();
		}

		repository.move_new_connections_to_active().unwrap();
		repository
	}
}
