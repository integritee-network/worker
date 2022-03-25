use std::{
	collections::HashMap,
	time::{Duration, Instant},
};

pub struct StopWatch {
	start: Instant,
	measurements: HashMap<String, Duration>,
}

impl StopWatch {
	fn start() -> Self {
		StopWatch { start: Instant::now(), measurements: HashMap::new() }
	}

	fn take(&mut self, measurement_name: &str) {
		self.measurements.insert(String::from(measurement_name), self.start.elapsed());
	}

	fn get(&self, measurement_name: &str) -> Option<&Duration> {
		self.measurements.get(measurement_name)
	}
}

#[cfg(test)]
pub mod tests {
	use super::*;
	use std::thread;

	#[test]
	fn test_run_one_benchmark() {
		let mut t = StopWatch::start();
		thread::sleep(Duration::from_millis(10));
		t.take(&String::from("benchmark1"));

		match t.get(&String::from("benchmark1")) {
			None => {
				assert!(false, "benchmark should exist");
			},
			Some(result) => {
				println!("actual: {}", result.as_millis());
				assert!(result.as_millis() >= Duration::from_millis(10).as_millis());
			},
		}
	}

	#[test]
	fn test_run_two_benchmarks() {
		let mut t = StopWatch::start();
		thread::sleep(Duration::from_millis(10));
		t.take(&String::from("benchmark1"));
		thread::sleep(Duration::from_millis(10));
		t.take(&String::from("benchmark2"));

		match t.get(&String::from("benchmark1")) {
			None => {
				assert!(false, "benchmark should exist");
			},
			Some(result) => {
				println!("actual: {}", result.as_millis());
				assert!(result.as_millis() >= Duration::from_millis(10).as_millis());
				assert!(result.as_millis() < Duration::from_millis(11).as_millis());
			},
		}

		match t.get(&String::from("benchmark2")) {
			None => {
				assert!(false, "benchmark should exist");
			},
			Some(result) => {
				println!("actual: {}", result.as_millis());
				assert!(result.as_millis() >= Duration::from_millis(20).as_millis());
				assert!(result.as_millis() < Duration::from_millis(21).as_millis());
			},
		}
	}
}
