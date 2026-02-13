use oakbuild::{
    SigningMaterial, SigningRequest, load_signing_material, read_all_bytes, write_output_from_stub,
};
use serde::Deserialize;
use std::env;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const EMBEDDED_RUNNER: &[u8] = include_bytes!(env!("OAKBUILD_EMBEDDED_RUNNER_PATH"));

#[derive(Debug)]
struct BuildArgs {
    script: PathBuf,
    out: PathBuf,
    private_key: Option<PathBuf>,
    signer: Option<String>,
}

#[derive(Debug)]
enum ParsedCommand {
    Build(BuildArgs),
    Help,
    ShortVersion,
    LongVersion,
}

#[derive(Debug, Default, Deserialize)]
struct BuilderConfig {
    private_key: Option<String>,
    signer: Option<String>,
}

fn program_name_from_path(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "oakbuild".to_string())
}

fn main_help_text(prog: &str) -> String {
    format!(
        "Convert a script into a self-contained signed executable

Usage: {prog} --script <SCRIPT> --out <OUT> [OPTIONS]

Options:
      --script <SCRIPT>
      --out <OUT>
      --private-key <PRIVATE_KEY>
      --signer <SIGNER>
  -h, --help                     Print help
  -V                             Print short version
      --version                  Print long version"
    )
}

fn short_version_text() -> String {
    format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

fn long_version_text() -> String {
    format!(
        "{} {}
Builder for oakbuild-runner payload artifacts
By Oak Bioinformatics (https://oakbioinformatics.com)
For bioinformatics systems development, contact info@oakbioinformatics.com",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    )
}

fn parse_build_args(args: &[String]) -> Result<BuildArgs, String> {
    let mut script: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut private_key: Option<PathBuf> = None;
    let mut signer: Option<String> = None;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--script" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value for '--script'".to_string());
                }
                script = Some(PathBuf::from(&args[i]));
            }
            "--out" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value for '--out'".to_string());
                }
                out = Some(PathBuf::from(&args[i]));
            }
            "--private-key" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value for '--private-key'".to_string());
                }
                private_key = Some(PathBuf::from(&args[i]));
            }
            "--signer" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value for '--signer'".to_string());
                }
                signer = Some(args[i].clone());
            }
            a if a.starts_with("--script=") => {
                script = Some(PathBuf::from(a.trim_start_matches("--script=")));
            }
            a if a.starts_with("--out=") => {
                out = Some(PathBuf::from(a.trim_start_matches("--out=")));
            }
            a if a.starts_with("--private-key=") => {
                private_key = Some(PathBuf::from(a.trim_start_matches("--private-key=")));
            }
            a if a.starts_with("--signer=") => {
                signer = Some(a.trim_start_matches("--signer=").to_string());
            }
            other => return Err(format!("unexpected argument '{other}'")),
        }
        i += 1;
    }

    let script = script.ok_or_else(|| "the '--script' argument is required".to_string())?;
    let out = out.ok_or_else(|| "the '--out' argument is required".to_string())?;

    Ok(BuildArgs {
        script,
        out,
        private_key,
        signer,
    })
}

fn parse_cli(args: &[String]) -> Result<ParsedCommand, String> {
    if args.is_empty() {
        return Ok(ParsedCommand::Help);
    }

    if args.len() == 1 {
        match args[0].as_str() {
            "-h" | "--help" | "help" => return Ok(ParsedCommand::Help),
            "-V" => return Ok(ParsedCommand::ShortVersion),
            "--version" => return Ok(ParsedCommand::LongVersion),
            _ => {}
        }
    }

    if args.iter().any(|a| a == "-h" || a == "--help") {
        return Ok(ParsedCommand::Help);
    }

    if args.iter().any(|a| a == "-V" || a == "--version") {
        return Err("version flags must be used without other arguments".to_string());
    }

    Ok(ParsedCommand::Build(parse_build_args(args)?))
}

fn default_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join("oakbuild").join("config.toml"))
}

fn load_builder_config() -> io::Result<BuilderConfig> {
    let Some(path) = default_config_path() else {
        return Ok(BuilderConfig::default());
    };

    if !path.exists() {
        return Ok(BuilderConfig::default());
    }

    let raw = fs::read_to_string(&path)?;
    toml::from_str::<BuilderConfig>(&raw).map_err(|err| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!("failed to parse config '{}': {err}", path.display()),
        )
    })
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn env_non_empty(name: &str) -> Option<String> {
    non_empty(env::var(name).ok())
}

fn resolve_private_key(args: &BuildArgs, config: &BuilderConfig) -> Option<PathBuf> {
    args.private_key
        .clone()
        .or_else(|| env_non_empty("OAKBUILD_PRIVATE_KEY").map(PathBuf::from))
        .or_else(|| non_empty(config.private_key.clone()).map(PathBuf::from))
}

fn resolve_signer(args: &BuildArgs, config: &BuilderConfig) -> Option<String> {
    non_empty(args.signer.clone())
        .or_else(|| env_non_empty("OAKBUILD_SIGNER"))
        .or_else(|| non_empty(config.signer.clone()))
}

fn now_unix_timestamp_utc() -> io::Result<String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| io::Error::other(format!("system clock is before Unix epoch: {err}")))?;
    Ok(duration.as_secs().to_string())
}

fn signing_mode(signing: Option<&SigningMaterial>) -> &'static str {
    match signing {
        None => "unsigned",
        Some(SigningMaterial::Ed25519 { .. }) => "signed (ed25519)",
        Some(SigningMaterial::Rsa { .. }) => "signed (rsa-pkcs1v15-sha256)",
    }
}

fn main() -> io::Result<()> {
    let argv: Vec<String> = env::args().collect();
    let prog = program_name_from_path(argv.first().map(String::as_str).unwrap_or("oakbuild"));

    let parsed = match parse_cli(&argv[1..]) {
        Ok(parsed) => parsed,
        Err(err) => {
            eprintln!("error: {err}");
            eprintln!();
            eprintln!("{}", main_help_text(&prog));
            std::process::exit(2);
        }
    };

    match parsed {
        ParsedCommand::Help => {
            println!("{}", main_help_text(&prog));
        }
        ParsedCommand::ShortVersion => {
            println!("{}", short_version_text());
        }
        ParsedCommand::LongVersion => {
            println!("{}", long_version_text());
        }
        ParsedCommand::Build(args) => {
            let config = load_builder_config()?;
            let script = read_all_bytes(&args.script)?;

            let private_key = resolve_private_key(&args, &config);
            let signer_value = resolve_signer(&args, &config);

            let signing_material = private_key
                .as_deref()
                .map(load_signing_material)
                .transpose()?;

            let signed_at = if signing_material.is_some() {
                Some(now_unix_timestamp_utc()?)
            } else {
                None
            };

            let signer = if signing_material.is_some() {
                Some(signer_value.ok_or_else(|| {
                    io::Error::new(
                        ErrorKind::InvalidInput,
                        "missing signer identity for signed build; provide --signer, OAKBUILD_SIGNER, or config value",
                    )
                })?)
            } else {
                None
            };

            let signing_request = match signing_material.as_ref() {
                Some(material) => Some(SigningRequest {
                    material,
                    signer: signer
                        .as_deref()
                        .expect("signer must exist for signed build"),
                    signed_at: signed_at
                        .as_deref()
                        .expect("signed_at must exist for signed build"),
                }),
                None => None,
            };

            write_output_from_stub(EMBEDDED_RUNNER, &args.out, &script, signing_request)?;

            println!("Wrote: {}", args.out.display());
            println!("mode: {}", signing_mode(signing_material.as_ref()));
            if let Some(signer) = signer {
                println!("signer: {}", signer);
            }
            if let Some(signed_at) = signed_at {
                println!("signed_at_utc: {}", signed_at);
            }
        }
    }

    Ok(())
}
