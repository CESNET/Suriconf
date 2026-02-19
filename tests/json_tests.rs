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

    #[test]
    fn get_the_last_one_stats() {
        let json = PathBuf::from("./tests/flows.json");
        let buf_json= json::open_json(&json).expect("File cannot be opened.");
        let result = json::get_the_last_one_stats(buf_json);
        assert!(result.is_ok(), "The last stat is taken.")
    }
}