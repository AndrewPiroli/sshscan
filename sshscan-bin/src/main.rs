use std::io::Read;
use sshscan_core::xml;

pub fn main() {
    let mut a = std::env::args();
    let mut f = std::fs::File::open(a.nth(1).unwrap()).unwrap();
    let mut fc = String::new();
    let _ = f.read_to_string(&mut fc);
    let res = xml::process_xml(&mut fc).unwrap();
    for found in res {
        println!("{found:#?}");
    }
}
