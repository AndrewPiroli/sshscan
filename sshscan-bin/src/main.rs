use std::{io::Write, path::PathBuf, process::ExitCode};

const HELP: &str = "\
Usage: sshscan [OPTIONS] <COMMAND>

Commands:
  generate <input_file>              Generate a report from existing nmap XML scan data
  scan <cidr> [port] [aggressive]    Run nmap and generate a report

Options:
  -o, --output <FILE>    Output file to write (use '-' for stdout) [default: stdout]
  -i, --include-down     Include hosts that are down in the report [default: false]
  -h, --help             Print help
  -V, --version          Print version
";

const VERSION: &str = env!("CARGO_PKG_VERSION");

enum OutputType {
    Stdout,
    File(PathBuf),
}

struct SshScanConfig {
    output_file: OutputType,
    include_down: bool,
}

enum Command {
    Generate {
        input_file: PathBuf,
    },
    Scan {
        cidr: String,
        port: u16,
        aggressive: bool,
    },
}

/// Parse arguments from the environment.
///
/// Returns `Ok((config, command))` on success, or `Err(code)` when execution
/// should stop immediately — including success cases like `--help`/`--version`.
fn parse_args() -> Result<(SshScanConfig, Command), ExitCode> {
    let mut pargs = pico_args::Arguments::from_env();

    if pargs.contains(["-h", "--help"]) {
        print!("{HELP}");
        return Err(ExitCode::SUCCESS);
    }
    if pargs.contains(["-V", "--version"]) {
        println!("sshscan {VERSION}");
        return Err(ExitCode::SUCCESS);
    }

    // Global options — consume before the subcommand name so they work in either position.
    let output_file_raw: Option<String> =
        pargs.opt_value_from_str(["-o", "--output"]).map_err(|e| {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        })?;
    let include_down = pargs.contains(["-i", "--include-down"]);

    let output_file = match output_file_raw {
        None => OutputType::Stdout,
        Some(ref s) if s == "-" => OutputType::Stdout,
        Some(s) => OutputType::File(PathBuf::from(s)),
    };

    let config = SshScanConfig {
        output_file,
        include_down,
    };

    // The next free argument is the subcommand name.
    let subcommand: String = pargs.free_from_str().map_err(|_| {
        eprintln!("Error: no subcommand provided\n");
        eprint!("{HELP}");
        ExitCode::FAILURE
    })?;

    let command = match subcommand.as_str() {
        "generate" => {
            // Re-check help flag after subcommand to support `sshscan generate --help`
            if pargs.contains(["-h", "--help"]) {
                println!("Usage: sshscan [OPTIONS] generate <input_file>\n");
                println!("  <input_file>    nmap XML file to read from");
                return Err(ExitCode::SUCCESS);
            }
            let input_file: PathBuf = pargs.free_from_str().map_err(|_| {
                eprintln!("Error: 'generate' requires <input_file>");
                ExitCode::FAILURE
            })?;
            Command::Generate { input_file }
        }
        "scan" => {
            if pargs.contains(["-h", "--help"]) {
                println!("Usage: sshscan [OPTIONS] scan <cidr> [port] [aggressive]\n");
                println!("  <cidr>          Target range in CIDR notation (e.g. 10.0.0.0/24)");
                println!("  [port]          Port to scan [default: 22]");
                println!("  [aggressive]    Use aggressive timing (-T5) [default: true]");
                return Err(ExitCode::SUCCESS);
            }
            let cidr: String = pargs.free_from_str().map_err(|_| {
                eprintln!("Error: 'scan' requires <cidr>");
                ExitCode::FAILURE
            })?;
            let port: u16 = pargs.free_from_str().unwrap_or(22);
            let aggressive: bool = pargs.free_from_str().unwrap_or(true);
            Command::Scan {
                cidr,
                port,
                aggressive,
            }
        }
        other => {
            eprintln!("Error: unknown subcommand '{other}'\n");
            eprint!("{HELP}");
            return Err(ExitCode::FAILURE);
        }
    };

    // Warn about any unrecognised arguments rather than silently ignoring them.
    let remaining = pargs.finish();
    if !remaining.is_empty() {
        let unknown: Vec<_> = remaining.iter().map(|s| s.to_string_lossy()).collect();
        eprintln!("Error: unexpected argument(s): {}", unknown.join(", "));
        return Err(ExitCode::FAILURE);
    }

    Ok((config, command))
}

pub fn main() -> ExitCode {
    let (config, command) = match parse_args() {
        Ok(args) => args,
        Err(code) => return code,
    };

    match command {
        Command::Generate { input_file } => {
            let data = match std::fs::read_to_string(&input_file) {
                Ok(s) => s,
                Err(err) => {
                    eprintln!(
                        "Failed to read input file at: {}",
                        input_file.to_string_lossy()
                    );
                    eprintln!("Reason: {err}");
                    return ExitCode::FAILURE;
                }
            };
            let cur = std::io::Cursor::new(data);
            generate(cur, &config);
            ExitCode::SUCCESS
        }
        Command::Scan {
            cidr,
            port,
            aggressive,
        } => {
            if let Err(e) = scan_and_gen(&cidr, port, aggressive, &config) {
                eprintln!("Error: {e}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
    }
}

fn scan_and_gen(
    cidr: &str,
    port: u16,
    aggressive: bool,
    config: &SshScanConfig,
) -> Result<(), sshscan_core::SshScanErr> {
    use std::process::{Command as Cmd, Stdio};
    let Ok(nmap_exe) = which::which("nmap") else {
        return Err(sshscan_core::SshScanErr::Other(
            "nmap not found in $PATH".to_owned(),
        ));
    };
    let mut nmap_handle = Cmd::new(nmap_exe);
    if aggressive {
        nmap_handle.arg("-T5");
    } else {
        nmap_handle.arg("-T1");
    }
    nmap_handle.arg("-sV");
    #[allow(clippy::needless_borrows_for_generic_args)]
    // reduce binary size by sticking with just &str to Command::arg
    nmap_handle.arg(&format!("-p{port}"));
    nmap_handle.arg("--script");
    nmap_handle.arg("ssh2-enum-algos");
    nmap_handle.arg(cidr);
    nmap_handle.arg("-oX");
    nmap_handle.arg("-");
    nmap_handle.stdin(Stdio::null()).stdout(Stdio::piped());
    let process_output = nmap_handle.spawn().unwrap().wait_with_output().unwrap();
    let data = String::from_utf8(process_output.stdout).unwrap();
    let cur = std::io::Cursor::new(data);
    generate(cur, config);
    Ok(())
}

fn generate(input: impl std::io::Read, config: &SshScanConfig) {
    let res = sshscan_core::xml::process_xml(input, !config.include_down)
        .expect("Failed to process XML!");
    let mut processed_hosts = Vec::with_capacity(res.len());
    for found in res {
        match found {
            Ok(host) => processed_hosts.push(host),
            Err(e) => eprintln!("Error: {e:?}"),
        }
    }
    let agg_data = sshscan_core::agg_data::AggregatedData::build_from_hosts(&processed_hosts);
    let built_report = sshscan_core::html::generate(&processed_hosts, &agg_data);
    match &config.output_file {
        OutputType::File(path) => {
            let mut writer = std::io::BufWriter::new(
                std::fs::File::create(path).expect("Failed to open output file!"),
            );
            writer
                .write_all(built_report.as_bytes())
                .expect("Failed to write all data");
        }
        OutputType::Stdout => {
            println!("{built_report}");
        }
    }
}
