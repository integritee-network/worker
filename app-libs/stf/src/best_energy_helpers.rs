use crate::MerkleProofWithCodec;
use binary_merkle_tree::merkle_proof;
use codec::Encode;
use itp_stf_primitives::error::StfError;
use simplyr_lib::{MarketOutput, Order};
use sp_core::H256;
use sp_runtime::traits::Keccak256;
use std::{format, fs, vec::Vec};

pub static ORDERS_DIR: &str = "./records/orders";
pub static RESULTS_DIR: &str = "./records/market_results";

pub fn get_merkle_proof_for_actor_from_file(
	timestamp: &str,
	actor_id: &str,
) -> Result<MerkleProofWithCodec<H256, Vec<u8>>, StfError> {
	let orders = read_orders(timestamp)?;

	get_merkle_proof_for_actor(actor_id, &orders)
		.ok_or_else(|| StfError::Dispatch(format!("Leaf Index error: {:?}", actor_id)))
}

pub fn read_market_results(timestamp: &str) -> Result<MarketOutput, StfError> {
	let file = format!("{}/{}.json", RESULTS_DIR, timestamp);
	let content = fs::read_to_string(&file).map_err(|e| {
		StfError::Dispatch(format!("Reading Results File: {}, Error: {:?}", file, e))
	})?;

	serde_json::from_str(&content).map_err(|e| {
		StfError::Dispatch(format!("Deserializing Results {:?}. Error: {:?}", content, e))
	})
}

pub fn read_orders(timestamp: &str) -> Result<Vec<Order>, StfError> {
	let file = format!("{}/{}.json", ORDERS_DIR, timestamp);
	let content = fs::read_to_string(&file).map_err(|e| {
		StfError::Dispatch(format!("Reading Orders File: {}, Error: {:?}", file, e))
	})?;

	serde_json::from_str(&content).map_err(|e| {
		StfError::Dispatch(format!("Deserializing Orders {:?}. Error: {:?}", content, e))
	})
}

pub fn write_orders(timestamp: &str, orders: &[Order]) -> Result<(), StfError> {
	let orders_path = format!("{}/{}.json", ORDERS_DIR, timestamp);

	let orders_serialized = serde_json::to_string(&orders).map_err(|e| {
		StfError::Dispatch(format!("Serializing orders {:?}. Error: {:?}", orders, e))
	})?;

	fs::write(&orders_path, orders_serialized)
		.map_err(|e| StfError::Dispatch(format!("Writing orders {:?}. Error: {:?}", orders, e)))
}

pub fn write_results(timestamp: &str, market_results: MarketOutput) -> Result<(), StfError> {
	let results_path = format!("{}/{}.json", RESULTS_DIR, timestamp);

	let results_serialized = serde_json::to_string(&market_results).map_err(|e| {
		StfError::Dispatch(format!(
			"Serializing market results {:?}. Error: {:?}",
			market_results, e
		))
	})?;

	fs::write(&results_path, results_serialized.as_bytes()).map_err(|e| {
		StfError::Dispatch(format!(
			"Writing market results {:?}. Error: {:?}",
			results_serialized, e
		))
	})
}

/// Gets the merkle proof of an `actor_id` if it is in the order set.
pub fn get_merkle_proof_for_actor(
	actor_id: &str,
	orders: &[Order],
) -> Option<MerkleProofWithCodec<H256, Vec<u8>>> {
	let leaf_index = get_leaf_index_for_actor(actor_id, orders)?;
	Some(merkle_proof::<Keccak256, _, _>(orders.iter().map(Encode::encode), leaf_index).into())
}

pub fn get_leaf_index_for_actor(actor_id: &str, orders: &[Order]) -> Option<usize> {
	orders.iter().position(|order| order.actor_id == actor_id)
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn get_leaf_index_of_orders_works() {
		let orders = default_orders();

		assert_eq!(get_leaf_index_for_actor("actor_0", &orders), Some(0));
		assert_eq!(get_leaf_index_for_actor("actor_1", &orders), Some(1));
		assert_eq!(get_leaf_index_for_actor("actor_2", &orders), Some(2));

		assert_eq!(get_leaf_index_for_actor("I do not exist", &orders), None);
	}

	#[test]
	fn get_merkle_proof_for_actor_works() {
		let orders = default_orders();
		let actor_0_order = orders[0].clone();

		let proof = get_merkle_proof_for_actor("actor_0", &orders).unwrap();

		// Test that we have returned the correct leaf. This is what a
		// client can do to ensure that it has received a proof for the
		// expected leaf.
		assert_eq!(proof.leaf, actor_0_order.encode());
		assert_eq!(proof.leaf_index, 0);
	}
}

pub fn default_orders() -> Vec<Order> {
	let orders_raw = r#"[{
      "id": 0,
      "order_type": "ask",
      "time_slot": "2022-03-04T05:06:07+00:00",
      "actor_id": "actor_0",
      "cluster_index": 0,
      "energy_kwh": 5.0,
      "price_euro_per_kwh": 0.19
    },
    {
      "id": 1,
      "order_type": "ask",
      "time_slot": "2022-03-04T05:06:07+00:00",
      "actor_id": "actor_1",
      "cluster_index": 0,
      "energy_kwh": 8.8,
      "price_euro_per_kwh": 0.23
    },
    {
      "id": 2,
      "order_type": "ask",
      "time_slot": "2022-03-04T05:06:07+00:00",
      "actor_id": "actor_2",
      "cluster_index": 0,
      "energy_kwh": 7.5,
      "price_euro_per_kwh": 0.15
    }]"#;

	serde_json::from_str(orders_raw).unwrap()
}

/// SGX storage helpers for all best energy data.
pub mod storage {
	use itp_storage::{storage_map_key, StorageHasher};
	use std::{string::String, vec::Vec};

	/// Module prefix to prevent accidental overwrite of storage for equally named storages.
	const MODULE_PREFIX: &str = "best_energy";
	const MERKLE_ROOTS_KEY: &str = "merkle_roots";

	pub fn merkle_roots_map_key(timestamp: String) -> Vec<u8> {
		storage_map_key(
			MODULE_PREFIX,
			MERKLE_ROOTS_KEY,
			&timestamp,
			&StorageHasher::Blake2_128Concat,
		)
	}
}
