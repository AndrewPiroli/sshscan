use std::str::FromStr;

use xmltree::{Element, XMLNode};
use crate::SshScanErr;

#[derive(Debug, Default, Clone)]
pub struct Host {
    pub status: HostStatus,
    pub addr: String,
    pub port_states: Vec<Description>,
}

#[derive(Debug, Clone)]
pub enum HostStatus {
    Up,
    Down,
    Unknown,
}

impl FromStr for HostStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "up" => Self::Up,
            "down" => Self::Down,
            _ => Self::Unknown
        })
    }
}

impl Default for HostStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Default, Clone)]
pub struct Description {
    pub portid: u16,
    pub state: bool,
    pub algos: Algos
}

#[derive(Debug, Default, Clone)]
pub struct Algos {
    pub kex_algos: Vec<String>,
    pub host_key_algos: Vec<String>,
    pub encryption_algos: Vec<String>,
    pub mac_algos: Vec<String>,
    pub compression_algos: Vec<String>,
}

impl Algos {
    fn vec_from_xml_key(&mut self, key: &str) -> &mut Vec<String> {
        match key {
            "kex_algorithms" => { &mut self.kex_algos },
            "server_host_key_algorithms" => { &mut self.host_key_algos },
            "encryption_algorithms" => { &mut self.encryption_algos },
            "mac_algorithms" => { &mut self.mac_algos },
            "compression_algorithms" => { &mut self.compression_algos },
            _ => {panic!("fixme")},
        }
    }
}


pub fn process_xml(xml: &mut str) -> Result<Vec<Result<Host, SshScanErr>>, SshScanErr> {
    let mut res = Vec::new();
    let c = std::io::Cursor::new(xml);
    let root = Element::parse(c)?;
    for e in root.children.iter() {
        if let Some(elem) = e.as_element() {
            if elem.name == "host" {
                res.push(process_host(elem));
            }
        }
    }
    Ok(res)
}

fn process_host(host_elem: &Element) -> Result<Host, SshScanErr> {
    let mut host_addr = String::new();
    let mut host_status: HostStatus = HostStatus::Unknown;
    let mut descrs: Vec<Description> = Vec::new();
    for child in host_elem.children.iter() {
        if let Some(child) = child.as_element() {
            match child.name.as_str() {
                "status" => {
                    if let Some(addr) = child.attributes.get("state") {
                        host_status = addr.parse().expect("this impl doesn't fail");
                    }
                }
                "address" => {
                    if let Some(addr) = child.attributes.get("addr") {
                        host_addr.clone_from(addr);
                    }
                },
                "ports" => {
                    for port_elem in child.children.iter() {
                        descrs.push(process_host_port(port_elem)?);
                    }
                }
                _ => { continue; }
            }
        }
    }
    Ok(Host {
        status: host_status,
        addr: host_addr,
        port_states: descrs,
    })
}

fn process_host_port(port_elem: &XMLNode) -> Result<Description, SshScanErr> {
    let mut state = false;
    let mut port = 0u16;
    let mut algos = Default::default();
    if let Some(port_elem) = port_elem.as_element() {
        port = port_elem.attributes.get("portid").unwrap_or(&"0".to_owned()).parse().unwrap_or_default();
        for child in port_elem.children.iter() {
            if let Some(child) = child.as_element() {
                match child.name.as_str() {
                    "state" => {
                        state = child.attributes.get("state").unwrap_or(&"".to_owned()) == "open";
                    },
                    "script" => {
                        process_script(child, &mut algos)?;
                    },
                    _ => {},
                }
            }
        }
    }
    Ok(Description { portid: port, state, algos })
}

fn process_script(script_elem: &Element, algos: &mut Algos) -> Result<(), SshScanErr> {
    for table_elem in script_elem.children.iter() {
        let table_elem = table_elem.as_element().ok_or(SshScanErr::XMLInvalid)?;
        let key = table_elem.attributes.get("key").ok_or(SshScanErr::XMLInvalid)?.as_str();
        for row in table_elem.children.iter() {
            let row = row.as_element().ok_or(SshScanErr::XMLInvalid)?.children.get(0).ok_or(SshScanErr::XMLInvalid)?.as_text().ok_or(SshScanErr::XMLInvalid)?;
            algos.vec_from_xml_key(key).push(row.to_owned());
        }
    }
    Ok(())
}