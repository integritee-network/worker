use std::{
	collections::HashMap,
	time::{Duration, Instant},
};

pub struct StopWatch {
	start: Instant,
	measurements: HashMap<String, Duration>,
}

impl StopWatch {
	pub fn start() -> Self {
		StopWatch { start: Instant::now(), measurements: HashMap::new() }
	}

	pub fn take(&mut self, measurement_name: &str) {
		self.measurements.insert(String::from(measurement_name), self.start.elapsed());
	}

	pub fn print(&self) {
		for (key, value) in &self.measurements {
			println!("{} : {}ms", key, value.as_millis())
		}
	}
}
