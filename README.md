# oakbuild

`oakbuild` converts scripts into signed binaries.

For example, it can generate a `myscript` binary from `myscript.sh` or `myscript.py`.
Running `myscript` does the same thing as running the source script.

`oakbuild` currently supports shell and Python scripts.

Using a binary instead of a script has the following advantages:

- Prevents script tampering.
- Prevents script drift.
- Preserves provenance: who signed the script and when.

The recipient of a binary you signed can verify it came from you
by comparing the public key embedded in the binary with the public key
you shared with them.

## Install

```bash
cargo install oakbuild
```

## How to Use

```bash
oakbuild \
  --script ./myscript.sh \
  --out ./myscript \
  --private-key ./.ssh/id_rsa \
  --signer "Sherlock Holmes <sherlockholmes@example.com>"
```

`--private-key` accepts OpenSSH, Ed25519, and RSA keys.

Optionally, you can create unsigned binaries:

```bash
oakbuild \
  --script ./myscript.sh \
  --out ./myscript
```

Then run the script with the binary:

```bash
./myscript -- arg1 arg2
```

Use `--continue-on-error` to keep running after a command fails.
The `--trace` option shows each command line as it executes.
The runtime is detected from the embedded script's shebang line, but you can override it with `--shell` (`sh`, `bash`, `zsh`, `python`, and `python3` are supported).
`--continue-on-error` and `--trace` apply only to shell payloads.

You can verify a binary with:

```bash
./myscript verify
```

For detailed verification output:

```bash
./myscript verify --verbose
```

To print the embedded script version (SHA-256):

```bash
./myscript version
```

To see the embedded script content:

```bash
./myscript show
```

## Config

Instead of passing `--private-key` and `--signer` every time, you can use a TOML config file:

```toml
private_key = "/absolute/path/to/signing/key"
signer = "Sherlock Holmes <sherlockholmes@example.com>"
```

Default config paths:
- macOS: `~/Library/Application Support/oakbuild/config.toml`
- Linux: `${XDG_CONFIG_HOME:-~/.config}/oakbuild/config.toml`
- Windows: `%APPDATA%\oakbuild\config.toml`

Config priority:
- `--private-key` and `--signer` CLI options
- `OAKBUILD_PRIVATE_KEY` and `OAKBUILD_SIGNER` environment variables
- config file
