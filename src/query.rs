use serde_json::de::SliceRead;
use std::collections::HashMap;
use std::path::PathBuf;
use crate::structures::CreatedLogs;

struct Resources {
    logs: CreatedLogs,
    queries: HashMap<String, Query>
}

enum Value {
    Bool(bool)
}

struct Query {
    file: PathBuf, // TODO tohle se bude napojit, i kdyz to bude jinak pojmenovane
    query: String,
    value: Value
}
