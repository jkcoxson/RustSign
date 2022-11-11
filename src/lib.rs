// Jackson Coxson

pub mod anisette;
pub mod request;

#[derive(Debug)]
pub enum Error {
    HttpRequest,
    Parse,
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn fetch_anisette() {
        println!("heck");
        let password = std::env::var("apple_password").unwrap();
        let email = std::env::var("apple_email").unwrap();
        let ad = anisette::AnisetteData::from_url(anisette::SIDELOADLY_ANISETTE).unwrap();
        let _ = request::GsaClient::new(email, password, ad);
    }
}
