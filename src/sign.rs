// jkcoxson

use rusty_libimobiledevice::libimobiledevice::Device;

use crate::{anisette_data::AnisetteData, apple_api::authenticate, error::Error};

/// Signs an .ipa at the specified path.
pub fn sign(
    ipa_path: String,
    apple_id: String,
    password: String,
    device: &Device, // might change
    auth_callback: &dyn Fn() -> u16,
) -> Result<(), Error> {
    let anisette_data = match AnisetteData::fetch_anisette_data() {
        Ok(r) => r,
        Err(_) => return Err(Error::FetchAnisetteData),
    };
    authenticate(apple_id, password, anisette_data, auth_callback)?;
    todo!()
}
