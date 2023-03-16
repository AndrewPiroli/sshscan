use sshscan_core::xml;
use std::{path::PathBuf, io::Write};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    /// XML file to read
   input_file: PathBuf,
   #[arg(short = 'o', long = "output")]
   /// Output file to write
   output_file: Option<PathBuf>
}

pub fn main() {
    let args = Args::parse();
    let data = std::fs::read_to_string(args.input_file).expect("Could not read input file!");
    let cur = std::io::Cursor::new(data);
    let res = xml::process_xml(cur).expect("Failed to process XML!");
    let mut proccessed_hosts = Vec::with_capacity(res.len());
    for found in res {
        match found {
            Ok(host) => {proccessed_hosts.push(host)},
            Err(e) => {eprintln!("Error: {e:?}")}
        }
    }
    let agg_data = sshscan_core::agg_data::AggregatedData::build_from_hosts(&proccessed_hosts);
    let built_report = sshscan_core::html::generate(&proccessed_hosts, &agg_data);
    match args.output_file {
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
