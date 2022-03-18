// jkcoxson

use rusty_libimobiledevice::plist::Plist;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Application {
    pub(crate) name: String,
    pub(crate) bundle_identifier: String,
    pub(crate) version: String,
    pub(crate) path: String,
}

impl TryFrom<PathBuf> for Application {
    type Error = ();

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        let info_string = match std::fs::read_to_string(path.join("Info.plist")) {
            Ok(string) => string,
            Err(_) => return Err(()),
        };
        let info_plist = match Plist::from_xml(info_string) {
            Ok(plist) => plist,
            Err(_) => return Err(()),
        };

        Ok(Application {
            name: info_plist
                .dict_get_item("CFBundleDisplayName")?
                .get_string_val()?,
            bundle_identifier: info_plist
                .dict_get_item("CFBundleIdentifier")?
                .get_string_val()?,
            version: info_plist
                .dict_get_item("CFBundleShortVersionString")?
                .get_string_val()?,
            path: path.to_str().unwrap().to_string(),
        })
    }
}
