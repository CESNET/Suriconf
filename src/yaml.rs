use std::fs::File;
use std::io::prelude::*;
use yaml_rust2::{Yaml, YamlLoader};

pub fn open_yaml(file: &str) -> Vec<Yaml> {
    let mut file = File::open(file).expect("Unable to open file");
    let mut contents = String::new();

    file.read_to_string(&mut contents).expect("Unable to read file");
    let docs = YamlLoader::load_from_str(&contents).unwrap();

    // TODO Debug support
    let doc = &docs[0];
    println!("{:?}", doc);
    docs
}

// TODO hashmap
/*pub fn parse_yaml(: &mut Vec<String>, ) {

}*/