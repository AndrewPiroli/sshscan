use sshscan_core::xml;
use std::{path::PathBuf, io::Write};
use clap::{Parser, Subcommand};

enum OutputType {
    Stdout,
    File(PathBuf),
}

struct SshScanConfig {
    output_file: OutputType,
    include_down: bool,
}

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[command(subcommand)]
    command: Commands,
   #[arg(short = 'o', long = "output", global = true)]
   /// Output file to write
   output_file: Option<PathBuf>,
    #[arg(short = 'i', long = "include-down", global = true)]
   /// Include hosts that are down (default: false)
   include_down: Option<bool>
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generate a report based on existing scan data
    Generate {
        /// Input XML file to read from
        input_file: PathBuf
    },
    /// Scan and generate report
    Scan {
        /// Range to scan in CIDR format X.X.X.X/X
        cidr: String,
        /// Port to scan (default: 22)
        port: Option<u16>,
        /// Agressive mode (-T5) (default: true)
        aggressive: Option<bool>,
    }
}

pub fn main() {
    let args = Args::parse();
    let output_file = match &args.output_file {
        Some(f) => {
            if f.as_os_str() == "-" {
                OutputType::Stdout
            }
            else {
                OutputType::File(f.clone())
            }
        },
        None => OutputType::Stdout,
    };
    let include_down = match &args.include_down {
        Some(b) => *b,
        None => false,
    };
    let config = SshScanConfig { output_file, include_down };
    match &args.command {
        Commands::Generate { input_file } => {
            let data = std::fs::read_to_string(input_file).expect("Could not read input file!");
            let cur = std::io::Cursor::new(data);
            generate(cur, config)
        },
        Commands::Scan { cidr, port, aggressive } => {

            match scan_and_gen(cidr, port.unwrap_or(22), aggressive.unwrap_or(true), config) {
                Err(e) => eprintln!("Error: {}", e.to_string()),
                _ => {},
            }
        },
    }

}

fn scan_and_gen(cidr: impl AsRef<str>, port: u16, agressive: bool, config: SshScanConfig) -> Result<(), sshscan_core::SshScanErr> {
    use std::process::*;
    let nmap_exe = match which::which("nmap") {
        Ok(exe) => exe,
        Err(_) => {
            return Err(sshscan_core::SshScanErr::Other("nmap not found in $PATH".to_owned()));
        },
    };
    let mut nmap_handle = Command::new(nmap_exe);
    if agressive {
        nmap_handle.arg("-T5");
    } else {
        nmap_handle.arg("-T1");
    }
    nmap_handle.arg("-sV");
    nmap_handle.arg(format!("-p{port}"));
    nmap_handle.arg("--script");
    nmap_handle.arg("ssh2-enum-algos");
    nmap_handle.arg(cidr.as_ref());
    nmap_handle.arg("-oX");
    nmap_handle.arg("-");
    nmap_handle.stdin(Stdio::null()).stdout(Stdio::piped());
    let process_output = nmap_handle.spawn().unwrap().wait_with_output().unwrap();
    let data = String::from_utf8(process_output.stdout).unwrap();
    let cur = std::io::Cursor::new(data);
    generate(cur, config);
    Ok(())
}


fn generate(input: impl std::io::Read, config: SshScanConfig) {
    let res = xml::process_xml(input, !config.include_down).expect("Failed to process XML!");
    let mut proccessed_hosts = Vec::with_capacity(res.len());
    for found in res {
        match found {
            Ok(host) => {proccessed_hosts.push(host)},
            Err(e) => {eprintln!("Error: {e:?}")}
        }
    }
    let agg_data = sshscan_core::agg_data::AggregatedData::build_from_hosts(&proccessed_hosts);
    let built_report = sshscan_core::html::generate(&proccessed_hosts, &agg_data);
    match &config.output_file {
        OutputType::File(path) => {
            let mut writer = std::io::BufWriter::new(std::fs::File::create(path).expect("Failed to open output file!"));
            writer.write_all(built_report.as_bytes()).expect("Failed to write all data");
        },
        OutputType::Stdout => {
            println!("{built_report}");
        },
    }
}