// jkcoxson

use std::collections::HashMap;

use rusty_libimobiledevice::plist::{Plist, PlistArrayIter};

pub struct AppId {
    name: String,
    identifier: String,
    bundle_identifier: String,
    features: HashMap<String, Plist>,
}

impl TryFrom<Plist> for AppId {
    type Error = ();

    fn try_from(plist: Plist) -> Result<Self, Self::Error> {
        let name = plist.dict_get_item("name")?.get_string_val()?;
        let identifier = plist.dict_get_item("identifier")?.get_string_val()?;
        let bundle_identifier = plist.dict_get_item("bundleIdentifier")?.get_string_val()?;

        let mut return_features = HashMap::new();
        match plist.dict_get_item("features") {
            Ok(features) => match plist.dict_get_item("enabledFeatures") {
                Ok(enabled_features) => {
                    let mut array_iter: PlistArrayIter = enabled_features.into();
                    loop {
                        if let Some(feature) = array_iter.next_item() {
                            let feature_name = feature.get_string_val()?;
                            let feature_node = features.dict_get_item(&feature_name)?;
                            return_features.insert(feature_name, feature_node.clone());
                        } else {
                            break;
                        }
                    }
                }
                Err(_) => {}
            },
            Err(_) => {}
        }

        Ok(AppId {
            name,
            identifier,
            bundle_identifier,
            features: return_features,
        })
    }
}
