#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}

mod account;
mod anisette_data;
mod app_id;
mod apple_api;
mod application;
mod certificate;
pub mod external;
mod sign;
mod team;
