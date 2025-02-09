use serde::Serialize;
use serde::Deserialize;

#[derive(Serialize, Deserialize)]
struct Versions {
    stacks_node: String,
    stacks_signer: String,
    blockstack_cli: String,
    clarity_cli: String,
    relay_server: String,
    stacks_inspect: String,
}

pub fn get_build_version(binary: &str) -> String {
    let versions = get_build_versions();
    match binary {
        "stacks-node" => versions.stacks_node,
        "stacks-signer" => versions.stacks_signer,
        "blockstack-cli" => versions.blockstack_cli,
        "clarity-cli" => versions.clarity_cli,
        "relay-server" => versions.relay_server,
        "stacks-inspect" => versions.stacks_inspect,
        _ => panic!("Binary not found"),
    }
}

pub fn get_long_version(binary: &str) -> String {
    let build_version = get_build_version(binary);
    format!("{} ({}, {}, {})", build_version, get_target_build_type(), get_target_os(), get_target_arch())
}

fn get_target_arch() -> String {
    let architecture = if cfg!(target_arch = "x86") { 
        "x86" 
    } 
    else if cfg!(target_arch = "x86_64") { 
        "x86_64" 
    } 
    else if cfg!(target_arch = "arm") {
         "ARM" 
    } 
    else if cfg!(target_arch = "aarch64") {
         "AArch64" 
    } 
    else { 
        "unknown"
    };
    architecture.to_string()
}

fn get_target_os() -> String {
    let os = if cfg!(target_os = "linux") { 
        "Linux" 
    } 
    else if cfg!(target_os = "macos") { 
        "macOS" 
    } 
    else if cfg!(target_os = "windows") {
         "Windows" 
    } 
    else { 
        "unknown"
    };
    os.to_string()
}

fn get_target_build_type() -> String {
    let build_type = if cfg!(debug_assertions) { 
        "Debug" 
    } 
    else { 
        "Release" 
    };
    build_type.to_string()
}

fn get_build_versions() -> Versions {
    let versions_content = include_str!("../../versions.yaml");
    let versions: Versions = serde_yaml::from_str(versions_content).expect("Unable to read versions.yaml");
    versions
}
