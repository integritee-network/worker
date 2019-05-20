#[no_mangle]
pub extern fn update_counter(x: u32, y: u32) -> u32 {
    x + y + 10
}
