// Jackson Coxson

use std::sync::Arc;

use pbkdf2::{
    password_hash::{PasswordHasher, SaltString},
    Params, Pbkdf2,
};
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use srp::{
    client::{SrpClient, SrpClientVerifier},
    groups::G_2048,
};
use ureq::AgentBuilder;

use crate::anisette::AnisetteData;

const GSA_ENDPOINT: &str = "https://gsa.apple.com/grandslam/GsService2";
const APPLE_ROOT: &[u8] = &[
    48, 130, 4, 187, 48, 130, 3, 163, 160, 3, 2, 1, 2, 2, 1, 2, 48, 13, 6, 9, 42, 134, 72, 134,
    247, 13, 1, 1, 5, 5, 0, 48, 98, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 19, 48, 17,
    6, 3, 85, 4, 10, 19, 10, 65, 112, 112, 108, 101, 32, 73, 110, 99, 46, 49, 38, 48, 36, 6, 3, 85,
    4, 11, 19, 29, 65, 112, 112, 108, 101, 32, 67, 101, 114, 116, 105, 102, 105, 99, 97, 116, 105,
    111, 110, 32, 65, 117, 116, 104, 111, 114, 105, 116, 121, 49, 22, 48, 20, 6, 3, 85, 4, 3, 19,
    13, 65, 112, 112, 108, 101, 32, 82, 111, 111, 116, 32, 67, 65, 48, 30, 23, 13, 48, 54, 48, 52,
    50, 53, 50, 49, 52, 48, 51, 54, 90, 23, 13, 51, 53, 48, 50, 48, 57, 50, 49, 52, 48, 51, 54, 90,
    48, 98, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 19, 48, 17, 6, 3, 85, 4, 10, 19, 10,
    65, 112, 112, 108, 101, 32, 73, 110, 99, 46, 49, 38, 48, 36, 6, 3, 85, 4, 11, 19, 29, 65, 112,
    112, 108, 101, 32, 67, 101, 114, 116, 105, 102, 105, 99, 97, 116, 105, 111, 110, 32, 65, 117,
    116, 104, 111, 114, 105, 116, 121, 49, 22, 48, 20, 6, 3, 85, 4, 3, 19, 13, 65, 112, 112, 108,
    101, 32, 82, 111, 111, 116, 32, 67, 65, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247,
    13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 228, 145, 169, 9, 31,
    145, 219, 30, 71, 80, 235, 5, 237, 94, 121, 132, 45, 235, 54, 162, 87, 76, 85, 236, 139, 25,
    137, 222, 249, 75, 108, 245, 7, 171, 34, 48, 2, 232, 24, 62, 248, 80, 9, 211, 127, 65, 168,
    152, 249, 209, 202, 102, 156, 36, 107, 17, 208, 163, 187, 228, 27, 42, 195, 31, 149, 158, 122,
    12, 164, 71, 139, 91, 212, 22, 55, 51, 203, 196, 15, 77, 206, 20, 105, 209, 201, 25, 114, 245,
    93, 14, 213, 127, 95, 155, 242, 37, 3, 186, 85, 143, 77, 93, 13, 241, 100, 53, 35, 21, 75, 21,
    89, 29, 179, 148, 247, 246, 156, 158, 207, 80, 186, 193, 88, 80, 103, 143, 8, 180, 32, 247,
    203, 172, 44, 32, 111, 112, 182, 63, 1, 48, 140, 183, 67, 207, 15, 157, 61, 243, 43, 73, 40,
    26, 200, 254, 206, 181, 185, 14, 217, 94, 28, 214, 203, 61, 181, 58, 173, 244, 15, 14, 0, 146,
    11, 177, 33, 22, 46, 116, 213, 60, 13, 219, 98, 22, 171, 163, 113, 146, 71, 83, 85, 193, 175,
    47, 65, 179, 248, 251, 227, 112, 205, 230, 163, 76, 69, 126, 31, 76, 107, 80, 150, 65, 137,
    196, 116, 98, 11, 16, 131, 65, 135, 51, 138, 129, 177, 48, 88, 236, 90, 4, 50, 140, 104, 179,
    143, 29, 222, 101, 115, 255, 103, 94, 101, 188, 73, 216, 118, 159, 51, 20, 101, 161, 119, 148,
    201, 45, 2, 3, 1, 0, 1, 163, 130, 1, 122, 48, 130, 1, 118, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255,
    4, 4, 3, 2, 1, 6, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255, 48, 29, 6, 3,
    85, 29, 14, 4, 22, 4, 20, 43, 208, 105, 71, 148, 118, 9, 254, 244, 107, 141, 46, 64, 166, 247,
    71, 77, 127, 8, 94, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 43, 208, 105, 71, 148,
    118, 9, 254, 244, 107, 141, 46, 64, 166, 247, 71, 77, 127, 8, 94, 48, 130, 1, 17, 6, 3, 85, 29,
    32, 4, 130, 1, 8, 48, 130, 1, 4, 48, 130, 1, 0, 6, 9, 42, 134, 72, 134, 247, 99, 100, 5, 1, 48,
    129, 242, 48, 42, 6, 8, 43, 6, 1, 5, 5, 7, 2, 1, 22, 30, 104, 116, 116, 112, 115, 58, 47, 47,
    119, 119, 119, 46, 97, 112, 112, 108, 101, 46, 99, 111, 109, 47, 97, 112, 112, 108, 101, 99,
    97, 47, 48, 129, 195, 6, 8, 43, 6, 1, 5, 5, 7, 2, 2, 48, 129, 182, 26, 129, 179, 82, 101, 108,
    105, 97, 110, 99, 101, 32, 111, 110, 32, 116, 104, 105, 115, 32, 99, 101, 114, 116, 105, 102,
    105, 99, 97, 116, 101, 32, 98, 121, 32, 97, 110, 121, 32, 112, 97, 114, 116, 121, 32, 97, 115,
    115, 117, 109, 101, 115, 32, 97, 99, 99, 101, 112, 116, 97, 110, 99, 101, 32, 111, 102, 32,
    116, 104, 101, 32, 116, 104, 101, 110, 32, 97, 112, 112, 108, 105, 99, 97, 98, 108, 101, 32,
    115, 116, 97, 110, 100, 97, 114, 100, 32, 116, 101, 114, 109, 115, 32, 97, 110, 100, 32, 99,
    111, 110, 100, 105, 116, 105, 111, 110, 115, 32, 111, 102, 32, 117, 115, 101, 44, 32, 99, 101,
    114, 116, 105, 102, 105, 99, 97, 116, 101, 32, 112, 111, 108, 105, 99, 121, 32, 97, 110, 100,
    32, 99, 101, 114, 116, 105, 102, 105, 99, 97, 116, 105, 111, 110, 32, 112, 114, 97, 99, 116,
    105, 99, 101, 32, 115, 116, 97, 116, 101, 109, 101, 110, 116, 115, 46, 48, 13, 6, 9, 42, 134,
    72, 134, 247, 13, 1, 1, 5, 5, 0, 3, 130, 1, 1, 0, 92, 54, 153, 76, 45, 120, 183, 237, 140, 155,
    220, 243, 119, 155, 242, 118, 210, 119, 48, 79, 193, 31, 133, 131, 133, 27, 153, 61, 71, 55,
    242, 169, 155, 64, 142, 44, 212, 177, 144, 18, 216, 190, 244, 115, 155, 238, 210, 100, 15, 203,
    121, 79, 52, 216, 162, 62, 249, 120, 255, 107, 200, 7, 236, 125, 57, 131, 139, 83, 32, 211, 56,
    196, 177, 191, 154, 79, 10, 107, 255, 43, 252, 89, 167, 5, 9, 124, 23, 64, 86, 17, 30, 116,
    211, 183, 139, 35, 59, 71, 163, 213, 111, 36, 226, 235, 209, 183, 112, 223, 15, 69, 225, 39,
    202, 241, 109, 120, 237, 231, 181, 23, 23, 168, 220, 126, 34, 53, 202, 37, 213, 217, 15, 214,
    107, 212, 162, 36, 35, 17, 247, 161, 172, 143, 115, 129, 96, 198, 27, 91, 9, 47, 146, 178, 248,
    68, 72, 240, 96, 56, 158, 21, 245, 61, 38, 103, 32, 138, 51, 106, 247, 13, 130, 207, 222, 235,
    163, 47, 249, 83, 106, 91, 100, 192, 99, 51, 119, 247, 58, 7, 44, 86, 235, 218, 15, 33, 14,
    218, 186, 115, 25, 79, 181, 217, 54, 127, 193, 135, 85, 217, 167, 153, 185, 50, 66, 251, 216,
    213, 113, 158, 126, 161, 82, 183, 27, 189, 147, 66, 36, 18, 42, 199, 15, 29, 182, 77, 156, 94,
    99, 200, 75, 128, 23, 80, 170, 138, 213, 218, 228, 252, 208, 9, 7, 55, 176, 117, 117, 33,
];

pub struct GsaClient {
    // client: SrpClient<'a, Sha256>,
    // a: [u8; 64],
    // a_pub: Vec<u8>,
    // b_pub: Vec<u8>,
    // salt: Vec<u8>,
    // username: String,
    // password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitRequestBody {
    #[serde(rename = "A2k")]
    a_pub: plist::Value,
    cpd: plist::Dictionary,
    #[serde(rename = "o")]
    operation: String,
    ps: Vec<String>,
    #[serde(rename = "u")]
    username: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RequestHeader {
    #[serde(rename = "Version")]
    version: String,
}

impl GsaClient {
    pub fn new(username: String, password: String, anisette: AnisetteData) -> Self {
        let client = SrpClient::<Sha256>::new(&G_2048);
        let a: Vec<u8> = (0..64).map(|_| rand::random::<u8>()).collect();
        let a_pub = client.compute_public_ephemeral(&a);

        let header = RequestHeader {
            version: "1.0.1".to_string(),
        };
        let body = InitRequestBody {
            a_pub: plist::Value::Data(a_pub),
            cpd: anisette.to_cpd(),
            operation: "init".to_string(),
            ps: vec!["s2k".to_string(), "s2k_fo".to_string()],
            username: username.clone(),
        };

        #[derive(Debug, Serialize, Deserialize)]
        struct InitRequest {
            #[serde(rename = "Header")]
            header: RequestHeader,
            #[serde(rename = "Request")]
            request: InitRequestBody,
        }

        let packet = InitRequest {
            header: header.clone(),
            request: body,
        };

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &packet).unwrap();
        let buffer = String::from_utf8(buffer).unwrap();
        println!("Body: {buffer}");

        let mut store = RootCertStore::empty();
        store.add_parsable_certificates(&[APPLE_ROOT.to_vec()]);
        let rustls_cli = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(store)
            .with_no_client_auth();
        let agent = AgentBuilder::new().tls_config(Arc::new(rustls_cli)).build();
        let res = agent
            .post(GSA_ENDPOINT)
            .set("Content-Type", "text/x-xml-plist")
            .set("Accept", "*/*")
            .set("User-Agent", "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0")
            .set("X-MMe-Client-Info", &anisette.x_mme_client_info)
            .send_string(&buffer)
            .unwrap();

        let res = res.into_string().unwrap();

        println!("{res}");

        let res: plist::Dictionary = plist::from_bytes(res.as_bytes()).unwrap();
        let res: plist::Value = res.get("Response").unwrap().to_owned();
        let res = match res {
            plist::Value::Dictionary(dict) => dict,
            _ => panic!("Invalid response"),
        };
        let salt = res.get("s").unwrap().as_data().unwrap();
        let b_pub = res.get("B").unwrap().as_data().unwrap();
        let iters = res.get("i").unwrap().as_signed_integer().unwrap();
        let c = res.get("c").unwrap().as_string().unwrap();

        let salt_string = SaltString::b64_encode(salt).unwrap();

        let password = Pbkdf2
            .hash_password_customized(
                password.as_bytes(),
                None,
                None,
                Params {
                    rounds: iters as u32,
                    output_length: 32,
                },
                &salt_string,
            )
            .unwrap()
            .to_string();

        let verifier: SrpClientVerifier<Sha256> = client
            .process_reply(&a, username.as_bytes(), password.as_bytes(), salt, b_pub)
            .unwrap();

        let m = verifier.proof();
        println!("M: {:?}", m);

        #[derive(Debug, Serialize, Deserialize)]
        struct ChallengeRequestBody {
            #[serde(rename = "M1")]
            m: plist::Value,
            cpd: plist::Dictionary,
            c: String,
            #[serde(rename = "o")]
            operation: String,
            #[serde(rename = "u")]
            username: String,
        }

        let body = ChallengeRequestBody {
            m: plist::Value::Data(m.to_vec()),
            c: c.to_string(),
            cpd: anisette.to_cpd(),
            operation: "complete".to_string(),
            username,
        };

        #[derive(Debug, Serialize, Deserialize)]
        struct ChallengeRequest {
            #[serde(rename = "Header")]
            header: RequestHeader,
            #[serde(rename = "Request")]
            request: ChallengeRequestBody,
        }

        let packet = ChallengeRequest {
            header,
            request: body,
        };

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &packet).unwrap();
        let buffer = String::from_utf8(buffer).unwrap();
        println!("Body: {buffer}");

        let res = agent
            .post(GSA_ENDPOINT)
            .set("Content-Type", "text/x-xml-plist")
            .set("Accept", "*/*")
            .set("User-Agent", "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0")
            .set("X-MMe-Client-Info", &anisette.x_mme_client_info)
            .send_string(&buffer)
            .unwrap();

        let res = res.into_string().unwrap();

        println!("{res}");

        todo!()
    }
}
