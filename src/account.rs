// jkcoxson

use rusty_libimobiledevice::plist::{Plist, PlistType};

#[derive(Debug, Clone)]
pub struct Account {
    pub(crate) apple_id: String,
    pub(crate) identifier: f64,
    pub(crate) first_name: String,
    pub(crate) last_name: String,
    pub(crate) cookie: String,
}

impl TryFrom<Plist> for Account {
    type Error = ();

    fn try_from(plist: Plist) -> Result<Self, Self::Error> {
        let apple_id = plist.dict_get_item("email")?.get_string_val()?;
        let identifier = match plist.dict_get_item("personId")?.get_node_type() {
            PlistType::Integer => plist.dict_get_item("personId")?.get_uint_val()? as f64,
            PlistType::Real => plist.dict_get_item("personId")?.get_real_val()?,
            _ => return Err(()),
        };
        let first_name = match plist.dict_get_item("firstName") {
            Ok(item) => item.get_string_val()?,
            Err(_) => plist.dict_get_item("dsFirstName")?.get_string_val()?,
        };
        let last_name = match plist.dict_get_item("lastName") {
            Ok(item) => item.get_string_val()?,
            Err(_) => plist.dict_get_item("dsLastName")?.get_string_val()?,
        };
        let cookie = "".to_string();

        Ok(Account {
            apple_id,
            identifier,
            first_name,
            last_name,
            cookie,
        })
    }
}
