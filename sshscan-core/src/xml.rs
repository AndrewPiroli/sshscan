use crate::*;
use xmltree::{Element, XMLNode};


pub fn process_xml<R>(xml: R) -> Result<Vec<Result<Host, SshScanErr>>, SshScanErr>
where R: std::io::Read {
    let mut res = Vec::new();
    let root = Element::parse(xml)?;
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
                    if let Some(ty) = child.attributes.get("addrtype") {
                        if ty == "ipv4" || ty == "ipv6" {
                            if let Some(addr) = child.attributes.get("addr") {
                                host_addr.clone_from(addr);
                            }
                        }
                    }
                }
                "ports" => {
                    for port_elem in child.children.iter() {
                        descrs.push(process_host_port(port_elem)?);
                    }
                }
                _ => {
                    continue;
                }
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
        port = port_elem
            .attributes
            .get("portid")
            .unwrap_or(&"0".to_owned())
            .parse()
            .unwrap_or_default();
        for child in port_elem.children.iter() {
            if let Some(child) = child.as_element() {
                match child.name.as_str() {
                    "state" => {
                        state = child.attributes.get("state").unwrap_or(&"".to_owned()) == "open";
                    }
                    "script" => {
                        process_script(child, &mut algos)?;
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(Description {
        portid: port,
        state,
        algos,
    })
}

fn process_script(script_elem: &Element, algos: &mut Algos) -> Result<(), SshScanErr> {
    for table_elem in script_elem.children.iter() {
        let table_elem = table_elem.as_element().ok_or(SshScanErr::XMLInvalid)?;
        let key = table_elem
            .attributes
            .get("key")
            .ok_or(SshScanErr::XMLInvalid)?
            .as_str();
        for row in table_elem.children.iter() {
            let row = row
                .as_element()
                .ok_or(SshScanErr::XMLInvalid)?
                .children
                .get(0)
                .ok_or(SshScanErr::XMLInvalid)?
                .as_text()
                .ok_or(SshScanErr::XMLInvalid)?;
            algos.vec_from_xml_key(key).push(row.to_owned());
        }
    }
    Ok(())
}
