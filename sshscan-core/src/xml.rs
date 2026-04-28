use crate::{Host, SshScanErr, HostStatus, Description, Algos};
use xmltree::{Element, XMLNode};

/// Parse XML file from nmap ssh2-enum-algos.
/// # Errors
/// Outer Result turns error on error from Read or if the XML is so badly formed such that the root element is not parsable
/// Inner Result returns error if a specific host failed to parse due to XML valiadtion failure
pub fn process_xml<R>(xml: R, filter_down: bool) -> Result<Vec<Result<Host, SshScanErr>>, SshScanErr>
where R: std::io::Read {
    let mut res = Vec::new();
    let root = Element::parse(xml)?;
    for e in &root.children {
        if let Some(elem) = e.as_element() && elem.name == "host" {
            res.push(process_host(elem, filter_down));
        }
    }
    Ok(res)
}

fn process_host(host_elem: &Element, filter_down: bool) -> Result<Host, SshScanErr> {
    let mut host_addr = String::new();
    let mut host_status: HostStatus = HostStatus::Unknown;
    let mut descrs: Vec<Description> = Vec::new();
    for child in &host_elem.children {
        if let Some(child) = child.as_element() {
            match child.name.as_str() {
                "status" => {
                    if let Some(addr) = child.attributes.get("state") {
                        host_status = HostStatus::from(addr.as_str());
                    }
                },
                "address" => {
                    if let Some(ty) = child.attributes.get("addrtype") &&
                       (ty == "ipv4" || ty == "ipv6") &&
                       let Some(addr) = child.attributes.get("addr")
                    {
                        host_addr.clone_from(addr);
                    }
                },
                "ports" => {
                    for port_elem in &child.children {
                        let port = process_host_port(port_elem)?;
                        match (&port.state, filter_down) {
                            (false, true) => {},
                            _ => { descrs.push(port); }
                        }
                    }
                },
                _ => {}
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
    let mut algos = Algos::default();
    let mut product: Option<String> = None;
    if let Some(port_elem) = port_elem.as_element() {
        port = port_elem.attributes.get("portid").map_or(0, |pid_s| pid_s.parse().unwrap_or(0));
        for child in &port_elem.children {
            if let Some(child) = child.as_element() {
                match child.name.as_str() {
                    "state" => {
                        state = child.attributes.get("state").is_some_and(|maybe_open|maybe_open.eq_ignore_ascii_case("open"));
                    }
                    "script" => {
                        process_script(child, &mut algos)?;
                    }
                    "service" => {
                        let mut temp = String::new();
                        if let Some(prod) = child.attributes.get("product") {
                            temp += prod;
                            temp += " ";
                        }
                        if let Some(ver) = child.attributes.get("version") {
                            temp += ver;
                            temp += " ";
                        }
                        if let Some(xtra) = child.attributes.get("extrainfo") {
                            temp += xtra;
                            temp += " ";
                        }
                        if !temp.is_empty() {
                            temp.truncate(temp.rfind(' ').unwrap_or(usize::MAX));
                            product = Some(temp);
                        }
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
        product,
    })
}

fn process_script(script_elem: &Element, algos: &mut Algos) -> Result<(), SshScanErr> {
    match script_elem.attributes.get("id") {
        None => { return Ok(()) }
        Some(id) if id != "ssh2-enum-algos" => { return Ok(()) },
        _ => {}
    }
    for table_elem in &script_elem.children {
        let table_elem = table_elem.as_element().ok_or(SshScanErr::XMLInvalid)?;
        let key = table_elem
            .attributes
            .get("key")
            .ok_or(SshScanErr::XMLInvalid)?
            .as_str();
        for row in &table_elem.children {
            let row = row
                .as_element()
                .ok_or(SshScanErr::XMLInvalid)?
                .children
                .first()
                .ok_or(SshScanErr::XMLInvalid)?
                .as_text()
                .ok_or(SshScanErr::XMLInvalid)?;
            algos[key].push(row.to_owned());
        }
    }
    Ok(())
}
