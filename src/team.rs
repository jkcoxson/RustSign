// jkcoxson

use rusty_libimobiledevice::plist::Plist;

use crate::account::Account;

pub struct Team {
    name: String,
    identifier: String,
    kind: TeamKind,
    account: Account,
}

enum TeamKind {
    Unknown,
    Free,
    Individual,
    Organization,
}

impl Team {
    pub fn new(account: Account, plist: Plist) -> Result<Self, ()> {
        Ok(Team {
            name: plist.dict_get_item("name")?.get_string_val()?,
            identifier: plist.dict_get_item("teamId")?.get_string_val()?,
            kind: match plist.dict_get_item("kind")?.get_string_val()?.as_str() {
                "Individual" => {
                    let mut to_return = TeamKind::Individual;
                    match plist.dict_get_item("membership") {
                        Ok(p) => {
                            if p.array_get_size()? == 1 {
                                if p.array_get_item(0)?
                                    .get_string_val()?
                                    .to_lowercase()
                                    .contains("free")
                                {
                                    to_return = TeamKind::Free
                                }
                            }
                        }
                        Err(_) => to_return = TeamKind::Individual,
                    }

                    to_return
                }
                "Company/Organization" => TeamKind::Organization,
                _ => TeamKind::Unknown,
            },
            account,
        })
    }
}
