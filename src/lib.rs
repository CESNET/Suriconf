macro_rules! mods {
    ($($name:ident),*) => {
        $(pub mod $name;)*
    };
}

mods!(argument, structures, yaml, suricata, json, test_cpu_affinity, memory_usage, capture_mode, query);