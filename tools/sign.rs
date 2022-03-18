// jkcoxson

use rust_sign::external;

fn main() {
    // Get 3 CStrings with ""
    let mut c_strings = [
        unsafe { std::ffi::CString::new("").unwrap() },
        unsafe { std::ffi::CString::new("").unwrap() },
        unsafe { std::ffi::CString::new("").unwrap() },
    ];

    let x = unsafe {
        external::bridge_sign(
            c_strings[0].as_ptr(),
            c_strings[1].as_ptr(),
            c_strings[2].as_ptr(),
        )
    };
    println!("{:?}", x);
}
