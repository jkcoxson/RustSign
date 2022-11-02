// Jackson Coxson

pub mod anisette;

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
        let ad = anisette::AnisetteData::from_url(anisette::SIDELOADLY_ANISETTE).unwrap();
        println!("{:?}", ad);
    }
}
