// jkcoxson

/// Somehow this URL can generate anisette data. Don't ask me why.
const slurp_url: &str = "https://armconverter.com/anisette/irGb3Quww8zrhgqnzmrx";

pub struct AnisetteData {
    x_apple_i_md_m: String,
    x_apple_i_md: String,
    x_apple_i_md_lu: String,
    x_apple_i_md_rinfo: String,
    x_mme_device_id: String,
    x_apple_i_srl_no: String,
    x_mme_client_info: String,
    x_apple_locale: String,
    x_apple_i_timezone: String,
}

pub enum AnisetteErrorCode {
    ITunesNotInstalled,
    ICloudNotInstalled,
    MissingApplicationSupportFolder,
    MissingAOSKit,
    MissingFoundation,
    MissingObjc,
    InvalidiTunesInstallation,
}

impl AnisetteData {
    /// Slurp some anisette data from the internet.
    pub fn fetch_anisette_data() -> Result<Self, ()> {
        // Create a request to the url
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "User-Agent",
            match "Xcode".parse() {
                Ok(h) => h,
                Err(_) => return Err(()),
            },
        );

        let resp = match reqwest::blocking::get(slurp_url) {
            Ok(r) => r,
            Err(_) => return Err(()),
        };
        let resp = match resp.text() {
            Ok(r) => r,
            Err(_) => return Err(()),
        };

        // Parse the JSON response
        let json_response: serde_json::Value = match serde_json::from_str(&resp) {
            Ok(r) => r,
            Err(_) => return Err(()),
        };
        Ok(AnisetteData {
            x_apple_i_md_m: json_response["X-Apple-I-MD-M"].to_string(),
            x_apple_i_md: json_response["X-Apple-I-MD"].to_string(),
            x_apple_i_md_lu: json_response["X-Apple-I-MD-LU"].to_string(),
            x_apple_i_md_rinfo: json_response["X-Apple-I-MD-RINFO"].to_string(),
            x_mme_device_id: json_response["X-MME-Device-ID"].to_string(),
            x_apple_i_srl_no: json_response["X-Apple-I-SRL-NO"].to_string(),
            x_mme_client_info: json_response["X-MME-Client-Info"].to_string(),
            x_apple_locale: json_response["X-Apple-Locale"].to_string(),
            x_apple_i_timezone: json_response["X-Apple-I-Timezone"].to_string(),
        })
    }
}
