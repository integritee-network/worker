/*
extern {
    fn get_offset() -> u32;
}
*/
#[no_mangle]
pub extern fn add_one(x: u32) -> u32 {
    unsafe {
//        x + 1 + get_offset()
        x + 1
    }
}
