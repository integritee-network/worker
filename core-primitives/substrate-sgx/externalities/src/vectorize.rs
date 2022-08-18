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

//! Converts maps to vecs for serialization.
//! from https://github.com/DenisKolodin/vectorize

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{iter::FromIterator, vec::Vec};

pub fn serialize<'a, T, K, V, S>(target: T, ser: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
	T: IntoIterator<Item = (&'a K, &'a V)>,
	K: Serialize + 'a,
	V: Serialize + 'a,
{
	let container: Vec<_> = target.into_iter().collect();
	serde::Serialize::serialize(&container, ser)
}

pub fn deserialize<'de, T, K, V, D>(des: D) -> Result<T, D::Error>
where
	D: Deserializer<'de>,
	T: FromIterator<(K, V)>,
	K: Deserialize<'de>,
	V: Deserialize<'de>,
{
	let container: Vec<_> = serde::Deserialize::deserialize(des)?;
	Ok(container.into_iter().collect())
}

#[cfg(test)]
mod tests {
	use crate::vectorize;
	use serde::{Deserialize, Serialize};
	use std::collections::HashMap;

	#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
	struct MyKey {
		one: String,
		two: u16,
		more: Vec<u8>,
	}

	#[derive(Debug, Serialize, Deserialize)]
	struct MyComplexType {
		#[serde(with = "vectorize")]
		map: HashMap<MyKey, String>,
	}

	#[test]
	fn it_works() -> Result<(), Box<dyn std::error::Error>> {
		let key = MyKey { one: "1".into(), two: 2, more: vec![1, 2, 3] };
		let mut map = HashMap::new();
		map.insert(key.clone(), "value".into());
		let instance = MyComplexType { map };
		let serialized = postcard::to_allocvec(&instance)?;
		let deserialized: MyComplexType = postcard::from_bytes(&serialized)?;
		let expected_value = "value".to_string();
		assert_eq!(deserialized.map.get(&key), Some(&expected_value));
		Ok(())
	}
}
