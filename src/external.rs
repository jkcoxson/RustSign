// jkcoxson

use libc::c_char;

extern "C" {
    pub fn bridge_sign(
        ipa_path: *const c_char,
        apple_id: *const c_char,
        password: *const c_char,
    ) -> *const c_char;
}
