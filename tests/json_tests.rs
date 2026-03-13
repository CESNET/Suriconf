use::suriconf::json;
use std::path::PathBuf;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_open() {
        let json = PathBuf::from("./tests/flows.json");
        let result= json::open_json(&json);
        assert!(result.is_ok(), "File cannot be opened.");
    }
}