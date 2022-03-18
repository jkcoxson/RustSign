// jkcoxson

use rusty_libimobiledevice::plist::Plist;

pub struct Certificate {
    name: String,
    serial_number: String,
    identifier: Option<String>,
    machine_name: Option<String>,
    machine_identifier: Option<String>,
    data: Option<Vec<u8>>,
    private_key: Option<Vec<u8>>,
}

impl TryFrom<Plist> for Certificate {
    type Error = ();

    fn try_from(plist: Plist) -> Result<Self, Self::Error> {
        match plist.dict_get_item("certContent") {
            Ok(data_node) => {
                let bytes = data_node.get_data_val()?;
                return Ok(parse_data(bytes)?);
            }
            Err(_) => {}
        }
        todo!()
    }
}

fn parse_data(data: Vec<i8>) -> Result<Certificate, ()> {
    todo!()
}
