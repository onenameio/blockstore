use serde_derive::Serialize;
use serde_derive::Deserialize;
use std::fs::File;
use std::io::Write;
use std::env;

#[derive(Serialize, Deserialize, Debug)]
struct Versions {
    stacks_node: String,
    stacks_signer: String,
    blockstack_cli: String,
    clarity_cli: String,
    relay_server: String,
    stacks_inspect: String,
}

// get Versions struct from versions.yaml
fn get_build_versions() -> Versions {
    let file = File::open("versions.yaml").expect("Unable to open file");
    let versions: Versions = serde_yaml::from_reader(file).expect("Unable to read file");
    versions
}

// override build versions with environment variables if they exist otherwise use passed in Versions struct
fn set_build_versions() {

    let mut versions = get_build_versions();

    if let Ok(val) = env::var("STACKS_NODE_VERSION") {
        versions.stacks_node = val;
    }
    if let Ok(val) = env::var("STACKS_SIGNER_VERSION") {
        versions.stacks_signer = val;
    }
    if let Ok(val) = env::var("BLOCKSTACK_CLI_VERSION") {
        versions.blockstack_cli = val;
    }
    if let Ok(val) = env::var("CLARITY_CLI_VERSION") {
        versions.clarity_cli = val;
    }
    if let Ok(val) = env::var("RELAY_SERVER_VERSION") {
        versions.relay_server = val;
    }
    if let Ok(val) = env::var("STACKS_INSPECT_VERSION") {
        versions.stacks_inspect = val;
    }
    write_build_versions(&versions, "versions.yaml");
}



fn write_build_versions(versions: &Versions, path: &str) {
    let yaml_string = serde_yaml::to_string(&versions).unwrap();
    let mut file = File::create(path).expect("Unable to create file");
    file.write_all(yaml_string.as_bytes()).expect("Unable to write data to path");
}

fn main() {
    set_build_versions();
}
