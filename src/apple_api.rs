// jkcoxson

use crate::{account::Account, anisette_data::AnisetteData};

const k_authentication_protocol_version: &str = "A1234";
const k_protocol_version: &str = "QH65B2";
const k_app_id_key: &str = "ba2ec180e6ca6e6c6a542255453b24d6e6e5b2be0cc48bc1b0d8ad64cfe0228f";
const k_client_id: &str = "XABBG36SBA";

pub fn authenticate(
    apple_id: String,
    password: String,
    anisette: AnisetteData,
    verification_callback: &dyn Fn() -> u16,
) -> Result<Account, ()> {
    todo!()
}
