// Jackson Coxson

use serde::{Deserialize, Serialize};

use crate::Error;

pub const SIDELOADLY_ANISETTE: &str = "https://sideloadly.io/anisette/irGb3Quww8zrhgqnzmrx";

#[derive(Serialize, Deserialize, Debug)]
pub struct AnisetteData {
    #[serde(rename(deserialize = "X-Apple-I-Client-Time"))]
    x_apple_i_client_time: String,
    #[serde(rename(deserialize = "X-Apple-I-MD"), with = "base64")]
    x_apple_i_md: Vec<u8>,
    #[serde(rename(deserialize = "X-Apple-I-MD-LU"))]
    x_apple_i_md_lu: String,
    #[serde(rename(deserialize = "X-Apple-I-MD-M"))]
    x_apple_i_md_m: String,
    #[serde(rename(deserialize = "X-Apple-I-MD-RINFO"))]
    x_apple_i_md_rinfo: String,
    #[serde(rename(deserialize = "X-Apple-I-SRL-NO"))]
    x_apple_i_srl_no: String,
    #[serde(rename(deserialize = "X-Apple-I-TimeZone"))]
    x_apple_i_timezone: String,
    #[serde(rename(deserialize = "X-Apple-Locale"))]
    x_apple_locale: String,
    #[serde(rename(deserialize = "X-MMe-Client-Info"))]
    x_mme_client_info: String,
    #[serde(rename(deserialize = "X-Mme-Device-Id"))]
    x_mme_device_id: String,
}

impl AnisetteData {
    /// Fetches the data at an anisette server
    pub fn from_url(url: impl Into<String>) -> Result<Self, crate::Error> {
        let body = match ureq::get(&url.into()).call() {
            Ok(b) => match b.into_string() {
                Ok(b) => b,
                Err(_) => {
                    return Err(Error::HttpRequest);
                }
            },
            Err(_) => {
                return Err(Error::HttpRequest);
            }
        };

        let body = match serde_json::from_str::<AnisetteData>(&body) {
            Ok(b) => b,
            Err(_) => return Err(Error::Parse),
        };

        Ok(body)
    }
}

// Thanks internet
mod base64 {
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        let base64 = base64::encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        base64::decode(base64.as_bytes()).map_err(serde::de::Error::custom)
    }
}
