use serde_json::{json, Value};
use sers_cli::{
    backend_report, build_package_from_config, identity_init, identity_registration_request,
    identity_show, inspect_bytes, parse_public_key, read_package,
};
use std::path::Path;
use std::process::ExitCode;

fn usage() -> &'static str {
    "usage: sers backend detect | sers inspect <file.sers> [--publisher-key <lowercase-hex>] | sers package build <config.json> <output.sers> | sers identity init <key-file> | sers identity show <key-file> | sers identity registration-request <key-file> --application <id> | sers --version"
}

fn run(args: &[String]) -> Result<Value, (u8, String)> {
    match args {
        [flag] if flag == "--version" || flag == "-V" => {
            Ok(json!({ "name": "sers", "version": env!("CARGO_PKG_VERSION") }))
        }
        [command, action] if command == "backend" && action == "detect" => {
            backend_report().map_err(|error| (1, error))
        }
        [command, path] if command == "inspect" => {
            let bytes = read_package(Path::new(path)).map_err(|error| (1, error))?;
            inspect_bytes(&bytes, None).map_err(|error| (1, error))
        }
        [command, path, option, key] if command == "inspect" && option == "--publisher-key" => {
            let public_key = parse_public_key(key).map_err(|error| (2, error))?;
            let bytes = read_package(Path::new(path)).map_err(|error| (1, error))?;
            inspect_bytes(&bytes, Some(&public_key)).map_err(|error| (1, error))
        }
        [command, action, config, output] if command == "package" && action == "build" => {
            build_package_from_config(Path::new(config), Path::new(output))
                .map_err(|error| (1, error))
        }
        [command, action, key_file] if command == "identity" && action == "init" => {
            identity_init(Path::new(key_file)).map_err(|error| (1, error))
        }
        [command, action, key_file] if command == "identity" && action == "show" => {
            identity_show(Path::new(key_file)).map_err(|error| (1, error))
        }
        [command, action, key_file, option, application]
            if command == "identity"
                && action == "registration-request"
                && option == "--application" =>
        {
            identity_registration_request(Path::new(key_file), application)
                .map_err(|error| (1, error))
        }
        _ => Err((2, usage().to_owned())),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(output) => match serde_json::to_string_pretty(&output) {
            Ok(text) => {
                println!("{text}");
                ExitCode::SUCCESS
            }
            Err(_) => {
                eprintln!("{{\"error\":\"failed to encode JSON output\"}}");
                ExitCode::FAILURE
            }
        },
        Err((code, error)) => {
            eprintln!("{}", json!({ "error": error, "usage": usage() }));
            ExitCode::from(code)
        }
    }
}
