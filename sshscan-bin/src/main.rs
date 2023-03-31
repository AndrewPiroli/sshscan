use sshscan_core::xml;
use std::{path::PathBuf, io::Write};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[command(subcommand)]
    command: Commands,
   #[arg(short = 'o', long = "output", global = true)]
   /// Output file to write
   output_file: Option<PathBuf>
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
        aggressive: Option<bool>
    }
}

pub fn main() {
    let args = Args::parse();
    match &args.command {
        Commands::Generate { input_file } => {
            let data = std::fs::read_to_string(input_file).expect("Could not read input file!");
            let cur = std::io::Cursor::new(data);
            generate(cur, args.output_file)
        },
        Commands::Scan { cidr, port, aggressive } => {
            scan_and_gen(cidr, port.unwrap_or(22), aggressive.unwrap_or(true), args.output_file);
        },
    }

}

fn scan_and_gen(cidr: impl AsRef<str>, port: u16, agressive: bool, output_file: Option<PathBuf>) {
    use std::process::*;
    let nmap_exe = which::which("nmap").unwrap();
    let mut nmap_handle = Command::new(nmap_exe);
    if agressive {
        nmap_handle.arg("-T5");
    } else {
        nmap_handle.arg("-T1");
    }
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
    generate(cur, output_file)
}


fn generate(input: impl std::io::Read, output_file: Option<PathBuf>) {
    let res = xml::process_xml(input).expect("Failed to process XML!");
    let mut proccessed_hosts = Vec::with_capacity(res.len());
    for found in res {
        match found {
            Ok(host) => {proccessed_hosts.push(host)},
            Err(e) => {eprintln!("Error: {e:?}")}
        }
    }
    let agg_data = sshscan_core::agg_data::AggregatedData::build_from_hosts(&proccessed_hosts);
    let built_report = sshscan_core::html::generate(&proccessed_hosts, &agg_data);
    match output_file {
        Some(output_file) => {
            if output_file.as_os_str() == "-" {
                println!("{built_report}");
            }
            else {
                let mut writer = std::io::BufWriter::new(std::fs::File::create(output_file).expect("Failed to open output file!"));
                writer.write_all(built_report.as_bytes()).expect("Failed to write all data");
            }
        },
        None => {
            println!("{built_report}");
        },
    }
}