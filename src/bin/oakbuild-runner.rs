use oakbuild::{VerificationStatus, try_read_footer_and_payload, verify_payload};
use std::env;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShellKind {
    Bash,
    Sh,
    Zsh,
    Python,
    Python3,
}

impl ShellKind {
    fn program(self) -> &'static str {
        match self {
            ShellKind::Bash => "bash",
            ShellKind::Sh => "sh",
            ShellKind::Zsh => "zsh",
            ShellKind::Python => "python",
            ShellKind::Python3 => "python3",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "bash" => Some(ShellKind::Bash),
            "sh" => Some(ShellKind::Sh),
            "zsh" => Some(ShellKind::Zsh),
            "python" => Some(ShellKind::Python),
            "python3" => Some(ShellKind::Python3),
            _ => None,
        }
    }
}

#[derive(Debug, Default)]
struct RunArgs {
    continue_on_error: bool,
    trace: bool,
    shell: Option<ShellKind>,
    passthrough_args: Vec<String>,
}

#[derive(Debug, Default)]
struct VerifyArgs {
    verbose: bool,
}

#[derive(Debug)]
enum ParsedCommand {
    Verify(VerifyArgs),
    Show,
    Version,
    Run(RunArgs),
    Help(Option<String>),
    ShortVersion,
    LongVersion,
}

fn detect_shell_from_shebang(payload: &[u8]) -> Option<ShellKind> {
    let first_line = payload.split(|b| *b == b'\n').next()?;
    let line = std::str::from_utf8(first_line)
        .ok()?
        .trim_start_matches('\u{feff}')
        .trim_end_matches('\r');
    let shebang = line.strip_prefix("#!")?.trim();
    if shebang.is_empty() {
        return None;
    }

    let mut parts = shebang.split_whitespace();
    let first = parts.next()?;
    let token = if Path::new(first).file_name()?.to_str()? == "env" {
        parts.find(|part| !part.starts_with('-'))?
    } else {
        Path::new(first).file_name()?.to_str()?
    };

    match token {
        "bash" => Some(ShellKind::Bash),
        "sh" => Some(ShellKind::Sh),
        "zsh" => Some(ShellKind::Zsh),
        "python" => Some(ShellKind::Python),
        t if t.starts_with("python3") => Some(ShellKind::Python3),
        t if t.starts_with("python") => Some(ShellKind::Python),
        _ => None,
    }
}

fn program_name_from_path(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "oakbuild-runner".to_string())
}

fn main_help_text(prog: &str) -> String {
    format!(
        "Verify and run an embedded script

Usage: {prog} [OPTIONS] [-- <SCRIPT_ARGS>...]
       {prog} <COMMAND>

Commands:
  verify
  show
  version
  help    Print this message or the help of the given subcommand(s)

Arguments:
  [SCRIPT_ARGS]...

Options:
      --continue-on-error
      --trace
      --shell <SHELL>      [possible values: bash, sh, zsh, python, python3]
  -h, --help               Print help
  -V                       Print short version
      --version            Print long version"
    )
}

fn short_version_text() -> String {
    format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

fn long_version_text() -> String {
    format!(
        "{} {}
Runtime for embedded script payloads
By Oak Bioinformatics (https://oakbioinformatics.com)
For bioinformatics systems development, contact info@oakbioinformatics.com",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    )
}

fn verify_help_text(prog: &str) -> String {
    format!(
        "Usage: {prog} verify [--verbose]

Options:
      --verbose
  -h, --help             Print help"
    )
}

fn show_help_text(prog: &str) -> String {
    format!(
        "Usage: {prog} show

Options:
  -h, --help             Print help"
    )
}

fn version_help_text(prog: &str) -> String {
    format!(
        "Usage: {prog} version

Options:
  -h, --help             Print help"
    )
}

fn parse_shell_arg(value: &str) -> Result<ShellKind, String> {
    ShellKind::parse(value).ok_or_else(|| {
        format!(
            "invalid value '{value}' for '--shell' [possible values: bash, sh, zsh, python, python3]"
        )
    })
}

fn parse_run_args(args: &[String]) -> Result<ParsedCommand, String> {
    let mut out = RunArgs::default();
    let mut i = 0usize;
    let mut passthrough = false;

    while i < args.len() {
        if passthrough {
            out.passthrough_args.push(args[i].clone());
            i += 1;
            continue;
        }

        match args[i].as_str() {
            "--" => passthrough = true,
            "--continue-on-error" => out.continue_on_error = true,
            "--trace" => out.trace = true,
            "--shell" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value for '--shell'".to_string());
                }
                out.shell = Some(parse_shell_arg(&args[i])?);
            }
            a if a.starts_with("--shell=") => {
                out.shell = Some(parse_shell_arg(a.trim_start_matches("--shell="))?);
            }
            "-h" | "--help" => return Ok(ParsedCommand::Help(None)),
            "-V" => return Ok(ParsedCommand::ShortVersion),
            "--version" => return Ok(ParsedCommand::LongVersion),
            other if other.starts_with('-') => {
                return Err(format!("unexpected argument '{other}'"));
            }
            other => out.passthrough_args.push(other.to_string()),
        }
        i += 1;
    }

    Ok(ParsedCommand::Run(out))
}

fn parse_verify_args(args: &[String]) -> Result<VerifyArgs, String> {
    let mut out = VerifyArgs::default();

    for arg in args {
        match arg.as_str() {
            "--verbose" => out.verbose = true,
            other => return Err(format!("unexpected argument '{other}'")),
        }
    }

    Ok(out)
}

fn parse_cli(args: &[String]) -> Result<ParsedCommand, String> {
    if args.is_empty() {
        return Ok(ParsedCommand::Run(RunArgs::default()));
    }

    match args[0].as_str() {
        "-h" | "--help" => Ok(ParsedCommand::Help(None)),
        "-V" => Ok(ParsedCommand::ShortVersion),
        "--version" => Ok(ParsedCommand::LongVersion),
        "help" => {
            if args.len() == 1 {
                Ok(ParsedCommand::Help(None))
            } else if args.len() == 2 {
                Ok(ParsedCommand::Help(Some(args[1].clone())))
            } else {
                Err(format!("unexpected argument '{}'", args[2]))
            }
        }
        "verify" => {
            if args[1..].iter().any(|a| a == "-h" || a == "--help") {
                Ok(ParsedCommand::Help(Some("verify".to_string())))
            } else {
                Ok(ParsedCommand::Verify(parse_verify_args(&args[1..])?))
            }
        }
        "show" => {
            if args.len() == 2 && (args[1] == "-h" || args[1] == "--help") {
                Ok(ParsedCommand::Help(Some("show".to_string())))
            } else if args.len() > 1 {
                Err(format!("unexpected argument '{}'", args[1]))
            } else {
                Ok(ParsedCommand::Show)
            }
        }
        "version" => {
            if args.len() == 2 && (args[1] == "-h" || args[1] == "--help") {
                Ok(ParsedCommand::Help(Some("version".to_string())))
            } else if args.len() > 1 {
                Err(format!("unexpected argument '{}'", args[1]))
            } else {
                Ok(ParsedCommand::Version)
            }
        }
        _ => parse_run_args(args),
    }
}

fn validate_runtime_options(shell: ShellKind, run: &RunArgs) -> Result<(), String> {
    match shell {
        ShellKind::Python | ShellKind::Python3 => {
            if run.continue_on_error {
                return Err(
                    "'--continue-on-error' is only supported for shell payloads".to_string()
                );
            }
            if run.trace {
                return Err("'--trace' is only supported for shell payloads".to_string());
            }
            Ok(())
        }
        ShellKind::Bash | ShellKind::Sh | ShellKind::Zsh => Ok(()),
    }
}

fn rewrite_virtual_script_prefix(line: &str, script_name: &str) -> String {
    if let Some(rest) = line.strip_prefix("(eval)") {
        return format!("{script_name}{rest}");
    }
    if let Some(start) = line.find("(eval)") {
        let mut out = String::with_capacity(line.len() + script_name.len());
        out.push_str(&line[..start]);
        out.push_str(script_name);
        out.push_str(&line[start + "(eval)".len()..]);
        return out;
    }
    if let Some(rest) = line.strip_prefix("/dev/stdin") {
        return format!("{script_name}{rest}");
    }
    if let Some(start) = line.find("/dev/stdin") {
        let mut out = String::with_capacity(line.len() + script_name.len());
        out.push_str(&line[..start]);
        out.push_str(script_name);
        out.push_str(&line[start + "/dev/stdin".len()..]);
        return out;
    }
    if let Some(start) = line.find("/dev/fd/") {
        let after = &line[start..];
        if let Some(colon_pos) = after.find(':') {
            let mut out = String::with_capacity(line.len() + script_name.len());
            out.push_str(&line[..start]);
            out.push_str(script_name);
            out.push_str(&after[colon_pos..]);
            return out;
        }
    }
    line.to_string()
}

fn forward_child_stderr<R: Read>(reader: R, script_name: &str) -> io::Result<()> {
    let mut reader = BufReader::new(reader);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let read = reader.read_until(b'\n', &mut buf)?;
        if read == 0 {
            break;
        }
        let raw = String::from_utf8_lossy(&buf);
        let has_newline = raw.ends_with('\n');
        let line = raw.trim_end_matches('\n').trim_end_matches('\r');
        let rewritten = rewrite_virtual_script_prefix(line, script_name);
        if has_newline {
            eprintln!("{rewritten}");
        } else {
            eprint!("{rewritten}");
        }
    }
    Ok(())
}

fn run_payload(
    payload: &[u8],
    shell: ShellKind,
    continue_on_error: bool,
    trace: bool,
    passthrough_args: &[String],
) -> io::Result<i32> {
    let script_name = env::current_exe()?
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "embedded-script".to_string());

    let mut payload_to_run = payload
        .strip_prefix(b"\xEF\xBB\xBF")
        .unwrap_or(payload)
        .to_vec();

    let mut cmd = Command::new(shell.program());
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped());

    match shell {
        ShellKind::Bash => {
            let driver = r#"
set -o pipefail
__PAYLOAD=$(cat)
__PAYLOAD_LINES=$(printf "%s\n" "$__PAYLOAD" | wc -l | tr -d '[:space:]')
__IN_ERR_TRAP=0
__LAST_TRACE_CMD=
__LAST_TRACE_LINE=0

__trace_debug() {
  local st line cmd
  st=$1
  line=$2
  cmd=$3
  if [[ "$__IN_ERR_TRAP" == "1" ]]; then
    return
  fi
  if [[ "$line" -lt 1 || "$line" -gt "$__PAYLOAD_LINES" ]]; then
    return
  fi
  if [[ "$line" == "$__LAST_TRACE_LINE" && "$cmd" == "$__LAST_TRACE_CMD" && "$st" -ne 0 ]]; then
    __IN_ERR_TRAP=1
    return
  fi

  echo "${line}: ${cmd}" >&2
  __LAST_TRACE_LINE=$line
  __LAST_TRACE_CMD=$cmd
}

__on_err() {
  local rc
  rc=$1

  __IN_ERR_TRAP=1
  if [[ "${CONTINUE_ON_ERROR:-0}" == "1" ]]; then
    __IN_ERR_TRAP=0
  else
    exit "${rc}"
  fi
}

if [[ "${TRACE:-0}" == "1" ]]; then
  set -T
  trap '__trace_debug "$?" "$LINENO" "$BASH_COMMAND"' DEBUG
fi

trap '__on_err "$?" "$LINENO" "$BASH_COMMAND"' ERR

if [[ "${CONTINUE_ON_ERROR:-0}" == "1" ]]; then
  set +e
else
  set -eE
fi

exec 3<<<"$__PAYLOAD"
source /dev/fd/3
"#;

            cmd.arg("-c").arg(driver).arg(script_name.clone());

            if continue_on_error {
                cmd.env("CONTINUE_ON_ERROR", "1");
            }
            if trace {
                cmd.env("TRACE", "1");
            }
        }
        ShellKind::Sh | ShellKind::Zsh => {
            if !continue_on_error {
                cmd.arg("-e");
            }
            if trace {
                match shell {
                    ShellKind::Sh => {
                        payload_to_run
                            .splice(0..0, b"PS4='+ ${LINENO}: '\nset -x\n".iter().copied());
                    }
                    ShellKind::Zsh => {
                        payload_to_run.splice(0..0, b"PS4='%i: '\nset -x\n".iter().copied());
                    }
                    ShellKind::Bash | ShellKind::Python | ShellKind::Python3 => {}
                }
            }
            cmd.arg("-c")
                .arg("__PAYLOAD=$(cat); eval \"$__PAYLOAD\"")
                .arg(script_name.clone());
        }
        ShellKind::Python | ShellKind::Python3 => {
            let driver = r#"
import sys
code = sys.stdin.read()
globals_dict = {
    "__name__": "__main__",
    "__file__": sys.argv[0],
    "__package__": None,
}
exec(compile(code, sys.argv[0], "exec"), globals_dict)
"#;
            cmd.arg("-c").arg(driver).arg(script_name.clone());
        }
    }

    for a in passthrough_args {
        cmd.arg(a);
    }

    let mut child = cmd.spawn()?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("failed to open child stderr"))?;
    let script_name_for_stderr = script_name.clone();
    let stderr_thread =
        thread::spawn(move || forward_child_stderr(stderr, &script_name_for_stderr));

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&payload_to_run)?;
    } else {
        return Err(io::Error::other("failed to open child stdin"));
    }

    let status = child.wait()?;
    match stderr_thread.join() {
        Ok(result) => result?,
        Err(_) => return Err(io::Error::other("stderr forwarding thread panicked")),
    }

    Ok(status.code().unwrap_or(1))
}

fn main() -> io::Result<()> {
    let argv: Vec<String> = env::args().collect();
    let prog = program_name_from_path(
        argv.first()
            .map(String::as_str)
            .unwrap_or("oakbuild-runner"),
    );

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
        ParsedCommand::Help(topic) => {
            let text = match topic.as_deref() {
                None => main_help_text(&prog),
                Some("verify") => verify_help_text(&prog),
                Some("show") => show_help_text(&prog),
                Some("version") => version_help_text(&prog),
                Some(other) => {
                    eprintln!("error: unrecognized subcommand '{other}'");
                    std::process::exit(2);
                }
            };
            println!("{text}");
        }
        ParsedCommand::ShortVersion => {
            println!("{}", short_version_text());
        }
        ParsedCommand::LongVersion => {
            println!("{}", long_version_text());
        }
        ParsedCommand::Show => {
            let exe = env::current_exe()?;
            match try_read_footer_and_payload(&exe)? {
                None => {
                    println!("No attached script payload found.");
                    std::process::exit(1);
                }
                Some((payload, _footer)) => {
                    let text = String::from_utf8_lossy(&payload);
                    print!("{}", text);
                }
            }
        }
        ParsedCommand::Version => {
            let exe = env::current_exe()?;
            match try_read_footer_and_payload(&exe)? {
                None => {
                    println!("No attached script payload found.");
                    std::process::exit(1);
                }
                Some((_payload, footer)) => {
                    println!("{}", hex::encode(footer.sha256));
                }
            }
        }
        ParsedCommand::Verify(verify_args) => {
            let exe = env::current_exe()?;
            match try_read_footer_and_payload(&exe)? {
                None => {
                    println!("No attached script payload found.");
                    std::process::exit(1);
                }
                Some((payload, footer)) => {
                    let status = verify_payload(&payload, &footer);
                    if verify_args.verbose {
                        println!("payload_len: {}", footer.payload_len);
                        println!("sha256: {}", hex::encode(footer.sha256));
                        println!("signed: {}", footer.is_signed());
                        println!("algorithm: {}", footer.algorithm.as_str());
                        if footer.is_signed() {
                            println!("public_key: {}", hex::encode(footer.public_key));
                            println!("signer: {}", footer.signer);
                            println!("signed_at_utc: {}", footer.signed_at);
                        }
                    }
                    match status {
                        VerificationStatus::SignedValid | VerificationStatus::UnsignedValid => {
                            println!("valid");
                        }
                        VerificationStatus::HashMismatch => {
                            println!("integrity invalid");
                            std::process::exit(1);
                        }
                        VerificationStatus::SignatureInvalid => {
                            println!("signature invalid");
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
        ParsedCommand::Run(run) => {
            let exe = env::current_exe()?;
            let Some((payload, footer)) = try_read_footer_and_payload(&exe)? else {
                println!("No attached script payload found.");
                std::process::exit(1);
            };

            match verify_payload(&payload, &footer) {
                VerificationStatus::SignedValid | VerificationStatus::UnsignedValid => {}
                VerificationStatus::HashMismatch => {
                    println!("Refusing to run: payload integrity check failed.");
                    std::process::exit(1);
                }
                VerificationStatus::SignatureInvalid => {
                    println!("Refusing to run: signature verification failed.");
                    std::process::exit(1);
                }
            }

            let shell = run
                .shell
                .or(detect_shell_from_shebang(&payload))
                .unwrap_or(ShellKind::Bash);
            if let Err(err) = validate_runtime_options(shell, &run) {
                eprintln!("error: {err}");
                std::process::exit(2);
            }

            let code = run_payload(
                &payload,
                shell,
                run.continue_on_error,
                run.trace,
                &run.passthrough_args,
            )?;
            std::process::exit(code);
        }
    }

    Ok(())
}
