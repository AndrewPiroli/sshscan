use sshscan_core::xml;
use std::io::Read;

pub fn main() {
    let mut a = std::env::args();
    let mut f = std::fs::File::open(a.nth(1).unwrap()).unwrap();
    let mut fc = String::new();
    let _ = f.read_to_string(&mut fc);
    let res = xml::process_xml(&mut fc).unwrap();
    let mut proccessed_hosts = Vec::with_capacity(res.len());
    for found in res {
        if let Ok(found) = found {
            proccessed_hosts.push(found);
        }
    }
    let test_tab = sshscan_core::html::create_host_table(&proccessed_hosts[0]);
    println!("{}", sshscan_core::html::testing(test_tab));
}
