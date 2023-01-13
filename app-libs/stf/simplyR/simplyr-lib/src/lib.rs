#![no_std]

//! Serialize and deserialize orders and match them using different algorithms.
//!
//! This crate opts out of the standard library by enabling the `no_std` attribute. This should
//! make deployment in constrained environments (like a secure enclave) easier. We are allowed to
//! use the `alloc` crate, so the consequences of this are less drastic.

extern crate alloc;

// Since we are in no_std land we have to be import items that might allocate memory explicitly.
use crate::alloc::string::ToString;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
// We use this instead of [`HashMap`] in `no_std` because we don't have access to a secure source
// of random numbers to avoid hash collision attacks.
use alloc::collections::btree_map::BTreeMap;
// We use this instead of [`HashSet`]. See above.
use alloc::collections::btree_set::BTreeSet;

// We can annotate our structs with custom derives of these traits.
// Code for serializing and deserializing will then be generated for us.
use serde::{Deserialize, Serialize};

/// Smallest energy value (in kWh) that is used for a match.
const ENERGY_EPS: f64 = 0.001;

fn round_energy_value(energy: f64) -> f64 {
    (energy * 1000.0).round() / 1000.0
}

/// A enumeration of the two possible order types.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum OrderType {
    #[serde(rename = "bid")]
    Bid,
    #[serde(rename = "ask")]
    Ask,
}

/// A bid or an ask for a certain amount of energy at a certain price.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Order {
    /// The order ID
    pub id: u64,
    /// bid or ask
    pub order_type: OrderType,
    pub time_slot: String,
    pub actor_id: String,
    /// A cluster index can also be `null` so we use an [`Option`] here.
    pub cluster_index: Option<usize>,
    /// The amount of energy in kWh
    pub energy_kwh: f64,
    /// The price in € / kWh
    pub price_euro_per_kwh: f64,
}

/// The market input contains all orders of a time slot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MarketInput {
    pub orders: Vec<Order>,
}

/// A match between a bid and an ask.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Match {
    /// The order ID of the bid
    pub bid_id: u64,
    /// The order ID of the ask
    pub ask_id: u64,
    /// The amount of energy in kWh
    pub energy_kwh: f64,
    /// The price in € / kWh
    pub price_euro_per_kwh: f64,
}

/// The market output contains all matches of a time slot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MarketOutput {
    pub matches: Vec<Match>,
}

/// This type is only used to interface with JSON and may not be useful in a public interface.
pub type GridFeeMatrixRaw = Vec<Vec<f64>>;

/// The 2D grid matrix is stored as a flat vector for efficient lookup and less allocations.
/// The code avoids the words `column`, `row`, `x`, `y` because the struct represents a mapping
/// between a source cluster and a destination cluster and an explicit orientation would just
/// add a source of confusion.
///
/// ```
/// # use rust_matching_lib::*;
/// # fn foo() -> Result<(), String> {
/// let json_str = "[
///   [0, 1, 1.2],
///   [1, 0, 1],
///   [1, 1, 0]
/// ]";
/// let gfm = GridFeeMatrix::from_json_str(json_str)?;
/// assert_eq!(gfm.lookup(0, 2), 1.2);
/// # Ok(())
/// # }
/// # foo().unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct GridFeeMatrix {
    /// Width and height of the square matrix
    pub size: usize,
    /// Fee values in a flat vector
    pub flat_matrix: Vec<f64>,
}

impl GridFeeMatrix {
    /// Create a `GridFeeMatrix` by parsing a JSON string.
    pub fn from_json_str(json_str: &str) -> Result<Self, String> {
        match serde_json::from_str::<GridFeeMatrixRaw>(json_str) {
            Ok(raw) => Self::from_raw(&raw),
            Err(err) => Err(err.to_string()),
        }
    }

    /// Create a `GridFeeMatrix` from a `GridFeeMatrixRaw`.
    pub fn from_raw(raw: &GridFeeMatrixRaw) -> Result<Self, String> {
        let size = raw.len();
        let mut flat_matrix = vec![0.0; size * size];
        for (source_cluster_idx, vec_a) in raw.iter().enumerate() {
            if vec_a.len() != size {
                return Err("matrix needs to be square -> every row/column array has to have the same size.".into());
            }
            for (dest_cluster_idx, &value) in vec_a.iter().enumerate() {
                let flat_index = (source_cluster_idx * size) + dest_cluster_idx;
                flat_matrix[flat_index] = value;
            }
        }
        Ok(GridFeeMatrix { size, flat_matrix })
    }

    /// Return the fee between a source cluster and a destination cluster.
    /// Indices are zero-based.
    pub fn lookup(&self, source_cluster_idx: usize, dest_cluster_idx: usize) -> f64 {
        assert!(source_cluster_idx < self.size);
        assert!(dest_cluster_idx < self.size);
        self.flat_matrix[(source_cluster_idx * self.size) + dest_cluster_idx]
    }
}

/// A very simple (and flawed) implementation of Pay-as-Bid matching.
pub fn pay_as_bid_matching(input: &MarketInput) -> MarketOutput {
    let mut bids: Vec<Order> = vec![];
    let mut asks: Vec<Order> = vec![];

    // Gather bids and asks
    for order in input.orders.iter().cloned() {
        match order.order_type {
            OrderType::Bid => {
                bids.push(order);
            }
            OrderType::Ask => {
                asks.push(order);
            }
        }
    }

    let mut matches = vec![];

    // Sort by price
    bids.sort_by(|a, b| {
        a.price_euro_per_kwh
            .total_cmp(&b.price_euro_per_kwh)
            .reverse()
    });
    asks.sort_by(|a, b| a.price_euro_per_kwh.total_cmp(&b.price_euro_per_kwh));

    // Make bids immutable to avoid accidentally changing them
    let bids = bids;

    // match
    for bid in &bids {
        let mut remaining_energy = bid.energy_kwh;
        for ask in asks.iter_mut() {
            if (bid.price_euro_per_kwh >= ask.price_euro_per_kwh) && (ask.energy_kwh > ENERGY_EPS) {
                let matched_energy = ask.energy_kwh.min(remaining_energy);
                matches.push(Match {
                    bid_id: bid.id,
                    ask_id: ask.id,
                    energy_kwh: round_energy_value(matched_energy),
                    price_euro_per_kwh: bid.price_euro_per_kwh,
                });
                ask.energy_kwh -= matched_energy;
                remaining_energy -= matched_energy;
                if remaining_energy < ENERGY_EPS {
                    break;
                }
            }
        }
    }

    MarketOutput { matches }
}

struct FairMatchingOrder {
    orig_id: u64,
    cluster_index: usize,
    price_euro_per_kwh: f64,
    adjusted_price: f64,
}

/// An implementation of our custom BEST matching algorithm.
pub fn custom_fair_matching(
    input: &MarketInput,
    energy_unit_kwh: f64,
    grid_fee_matrix: &GridFeeMatrix,
) -> MarketOutput {
    // TODO: Check time_slot of all orders is equal
    // TODO: Quantize energy values to energy unit
    // TODO: Check if cluster exists
    // TODO: Check that order id is unique

    const LARGE_ORDER_THRESHOLD: f64 = 2_u64.pow(32) as f64;

    //NOTE: 2^63 - 1 is too large to be represented by a f64 correctly, so I chose a smaller value.
    const MARKET_MAKER_THRESHOLD: f64 = (2_u64.pow(36)) as f64;

    // Filter orders by their type and energy

    // Asks by the market maker
    let asks_mm: Vec<Order> = input
        .orders
        .iter()
        .cloned()
        .filter(|order| {
            order.order_type == OrderType::Ask && order.energy_kwh >= MARKET_MAKER_THRESHOLD
        })
        .collect();

    // Bids by the market maker
    let bids_mm: Vec<Order> = input
        .orders
        .iter()
        .cloned()
        .filter(|order| {
            order.order_type == OrderType::Bid && order.energy_kwh >= MARKET_MAKER_THRESHOLD
        })
        .collect();

    // Are there "normal" asks with a resonable energy value?
    let any_normal_asks: bool = input.orders.iter().any(|order| {
        order.order_type == OrderType::Ask && order.energy_kwh < LARGE_ORDER_THRESHOLD
    });

    // Are there "normal" bids with a resonable energy value?
    let any_normal_bids: bool = input.orders.iter().any(|order| {
        order.order_type == OrderType::Bid && order.energy_kwh < LARGE_ORDER_THRESHOLD
    });

    if (!any_normal_asks && !any_normal_bids)
        || (!any_normal_asks && asks_mm.is_empty())
        || (!any_normal_bids && bids_mm.is_empty())
    {
        // No asks or no bids -> No matches
        return MarketOutput { matches: vec![] };
    }

    // Utility function for filtering orders and converting to FairMatchingOrders
    fn get_fair_orders<F>(
        market_input: &MarketInput,
        energy_unit_kwh: f64,
        filter_fn: F,
    ) -> Vec<FairMatchingOrder>
    where
        F: Fn(&Order) -> bool,
    {
        let mut forders = vec![];
        for order in market_input.orders.iter().filter(|order| {
            order.energy_kwh < LARGE_ORDER_THRESHOLD
                && order.cluster_index.is_some()
                && filter_fn(order)
        }) {
            let num_entries = (order.energy_kwh / energy_unit_kwh).trunc() as usize;
            forders.reserve(num_entries);
            // Create multiple entries - one for each full energy unit
            for _ in 0..num_entries {
                forders.push(FairMatchingOrder {
                    orig_id: order.id,
                    cluster_index: order.cluster_index.unwrap(),
                    price_euro_per_kwh: order.price_euro_per_kwh,
                    adjusted_price: f64::NAN,
                });
            }
        }
        forders
    }

    let matches = vec![];

    // Keep track of clusters to match. Initial value: all cluster indices
    let mut clusters_to_match: BTreeSet<usize> = BTreeSet::from_iter(0..grid_fee_matrix.size);

    // Map from cluster index -> set of order indices
    // TODO: Add `mut` again, so exclude can actually be used
    let exclude: BTreeMap<usize, BTreeSet<u64>> =
        BTreeMap::from_iter((0..grid_fee_matrix.size).map(|x| (x, BTreeSet::new())));

    loop {
        // Get cluster ID or break loop if there are none
        let cluster_idx = match clusters_to_match.pop_first() {
            Some(cluster_idx) => cluster_idx,
            None => break,
        };

        // local bids
        let mut fair_bids: Vec<_> = get_fair_orders(input, energy_unit_kwh, |x| {
            x.order_type == OrderType::Bid && x.cluster_index == Some(cluster_idx)
        });

        if fair_bids.is_empty() {
            // Nothing to do in this cluster
            continue;
        }

        let exclude_set = &exclude[&cluster_idx];

        // Get all asks that are not excluded and set the adjusted price (price + grid fee)
        let mut fair_asks: Vec<_> = {
            let mut asks = get_fair_orders(input, energy_unit_kwh, |x| {
                x.order_type == OrderType::Ask && !exclude_set.contains(&x.id)
            });
            for ask in &mut asks {
                ask.adjusted_price =
                    ask.price_euro_per_kwh + grid_fee_matrix.lookup(cluster_idx, ask.cluster_index);
            }
            asks
        };

        // Sort by price, descending
        fair_bids.sort_by(|a, b| {
            a.price_euro_per_kwh
                .total_cmp(&b.price_euro_per_kwh)
                .reverse()
        });
        // Sort by adjusted price, ascending, then by price, descending
        fair_asks.sort_by(|a, b| {
            a.adjusted_price.total_cmp(&b.adjusted_price).then(
                a.price_euro_per_kwh
                    .total_cmp(&b.price_euro_per_kwh)
                    .reverse(),
            )
        });

        {
            let mut _matches = vec![];
            let mut bids_iter = fair_bids.iter();
            let bid = bids_iter.next();

            for ask in fair_asks {
                if let Some(bid) = bid {
                    if ask.adjusted_price <= bid.price_euro_per_kwh {
                        _matches.push(Match {
                            bid_id: bid.orig_id,
                            ask_id: ask.orig_id,
                            energy_kwh: energy_unit_kwh,
                            price_euro_per_kwh: ask.adjusted_price,
                        });
                    }
                } else {
                    break;
                }
            }
        }

        //TODO ...
    }

    MarketOutput { matches }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grid_matrix() {
        // Read grid fee matrix from JSON and test the interface
        let matrix_json = "\
        [\
            [0,1,1],\
            [1,0,1],\
            [2,3,0]\
        ]\
        ";

        let raw: GridFeeMatrixRaw = serde_json::from_str(&matrix_json).unwrap();
        let matrix = GridFeeMatrix::from_raw(&raw).unwrap();
        assert_eq!(matrix.lookup(0, 0), 0.0);
        assert_eq!(matrix.lookup(2, 0), 2.0);
        assert_eq!(matrix.lookup(2, 1), 3.0);
        assert_eq!(matrix.lookup(2, 2), 0.0);
    }

    #[test]
    fn test_custom_fair_matching() {
        let order_1 = Order {
            id: 1,
            order_type: OrderType::Ask,
            time_slot: "2022-03-04T05:06:07+00:00".to_string(),
            actor_id: "actor_1".to_string(),
            cluster_index: Some(0),
            energy_kwh: 2.0,
            price_euro_per_kwh: 0.30,
        };

        let order_2 = Order {
            id: 2,
            order_type: OrderType::Bid,
            time_slot: "2022-03-04T05:06:07+00:00".to_string(),
            actor_id: "actor_2".to_string(),
            cluster_index: Some(0),
            energy_kwh: 2.0,
            price_euro_per_kwh: 0.30,
        };

        let grid_fee_matrix = GridFeeMatrix::from_json_str("[[0, 1], [1, 0]]").unwrap();

        let market_input = MarketInput {
            orders: vec![order_1, order_2],
        };

        let market_output = custom_fair_matching(&market_input, 1.0, &grid_fee_matrix);
    }

    #[test]
    fn test_pay_as_bid() {
        {
            let order_1 = Order {
                id: 1,
                order_type: OrderType::Ask,
                time_slot: "2022-03-04T05:06:07+00:00".to_string(),
                actor_id: "actor_1".to_string(),
                cluster_index: Some(0),
                energy_kwh: 2.0,
                price_euro_per_kwh: 0.30,
            };

            let order_2 = Order {
                id: 2,
                order_type: OrderType::Bid,
                time_slot: "2022-03-04T05:06:07+00:00".to_string(),
                actor_id: "actor_2".to_string(),
                cluster_index: Some(0),
                energy_kwh: 2.0,
                price_euro_per_kwh: 0.30,
            };

            let market_input = MarketInput {
                orders: vec![order_1, order_2],
            };

            let market_output = pay_as_bid_matching(&market_input);

            assert_eq!(market_output.matches.len(), 1);
            let m = &market_output.matches[0];
            assert_eq!(m.energy_kwh, 2.0);
            assert_eq!(m.price_euro_per_kwh, 0.3);
        }

        {
            let order_1 = Order {
                id: 1,
                order_type: OrderType::Ask,
                time_slot: "2022-03-04T05:06:07+00:00".to_string(),
                actor_id: "actor_1".to_string(),
                cluster_index: Some(0),
                energy_kwh: 3.0,
                price_euro_per_kwh: 0.30,
            };

            let order_2 = Order {
                id: 2,
                order_type: OrderType::Bid,
                time_slot: "2022-03-04T05:06:07+00:00".to_string(),
                actor_id: "actor_2".to_string(),
                cluster_index: Some(0),
                energy_kwh: 2.0,
                price_euro_per_kwh: 0.40,
            };

            let order_3 = Order {
                id: 3,
                order_type: OrderType::Bid,
                time_slot: "2022-03-04T05:06:07+00:00".to_string(),
                actor_id: "actor_3".to_string(),
                cluster_index: Some(0),
                energy_kwh: 2.0,
                price_euro_per_kwh: 0.30,
            };

            let market_input = MarketInput {
                orders: vec![order_1, order_2, order_3],
            };

            let market_output = pay_as_bid_matching(&market_input);

            assert_eq!(market_output.matches.len(), 2);
            let m1 = &market_output.matches[0];
            assert_eq!(m1.energy_kwh, 2.0);
            assert_eq!(m1.price_euro_per_kwh, 0.4);
            let m2 = &market_output.matches[1];
            assert_eq!(m2.energy_kwh, 1.0);
            assert_eq!(m2.price_euro_per_kwh, 0.3);
        }

        {
            let order_1 = Order {
                id: 1,
                order_type: OrderType::Ask,
                time_slot: "2022-03-04T05:06:07+00:00".to_string(),
                actor_id: "actor_1".to_string(),
                cluster_index: Some(0),
                energy_kwh: 3.0,
                price_euro_per_kwh: 0.20,
            };

            let order_2 = Order {
                id: 2,
                order_type: OrderType::Ask,
                time_slot: "2022-03-04T05:06:07+00:00".to_string(),
                actor_id: "actor_2".to_string(),
                cluster_index: Some(0),
                energy_kwh: 2.0,
                price_euro_per_kwh: 0.25,
            };

            let order_3 = Order {
                id: 3,
                order_type: OrderType::Bid,
                time_slot: "2022-03-04T05:06:07+00:00".to_string(),
                actor_id: "actor_3".to_string(),
                cluster_index: Some(0),
                energy_kwh: 4.0,
                price_euro_per_kwh: 0.30,
            };

            let market_input = MarketInput {
                orders: vec![order_1, order_2, order_3],
            };

            let market_output = pay_as_bid_matching(&market_input);

            assert_eq!(market_output.matches.len(), 2);
            let m1 = &market_output.matches[0];
            assert_eq!(m1.energy_kwh, 3.0);
            assert_eq!(m1.price_euro_per_kwh, 0.3);
            let m2 = &market_output.matches[1];
            assert_eq!(m2.energy_kwh, 1.0);
            assert_eq!(m2.price_euro_per_kwh, 0.3);
        }
    }
}
