use crate::Host;
use std::collections::HashMap;

#[derive(Debug, Default, Clone)]
pub struct AggregatedData<'host> {
    kex_algos: HashMap<String, Vec<&'host Host>>,
    host_key_algos: HashMap<String, Vec<&'host Host>>,
    encryption_algos: HashMap<String, Vec<&'host Host>>,
    mac_algos: HashMap<String, Vec<&'host Host>>,
    compression_algos: HashMap<String, Vec<&'host Host>>,
}

impl<'host> AggregatedData<'host> {
    pub fn build_from_hosts(hosts: &'host [Host]) -> Self {
        let mut res = Self::default();
        for host in hosts {
            for host_port in &host.port_states {
                // kex
                for kex in host_port.algos.kex_algos.iter() {
                    if let Some(existing) = res.kex_algos.get_mut(kex) {
                        existing.push(host);
                    }
                    else {
                        res.kex_algos.insert(kex.to_owned(), vec![host]);
                    }
                }
                // host key
                for host_key in host_port.algos.host_key_algos.iter() {
                    if let Some(existing) = res.host_key_algos.get_mut(host_key) {
                        existing.push(host);
                    }
                    else {
                        res.host_key_algos.insert(host_key.to_owned(), vec![host]);
                    }
                }
                // encryption
                for encryption in host_port.algos.encryption_algos.iter() {
                    if let Some(existing) = res.encryption_algos.get_mut(encryption) {
                        existing.push(host);
                    }
                    else {
                        res.encryption_algos.insert(encryption.to_owned(), vec![host]);
                    }
                }
                // mac
                for mac in host_port.algos.mac_algos.iter() {
                    if let Some(existing) = res.mac_algos.get_mut(mac) {
                        existing.push(host);
                    }
                    else {
                        res.mac_algos.insert(mac.to_owned(), vec![host]);
                    }
                }
                // compression
                for compression in host_port.algos.compression_algos.iter() {
                    if let Some(existing) = res.compression_algos.get_mut(compression) {
                        existing.push(host);
                    }
                    else {
                        res.compression_algos.insert(compression.to_owned(), vec![host]);
                    }
                }
            }
        }
        res
    }
}

impl<'host> std::ops::Index<&'static str> for AggregatedData<'host> {
    type Output = HashMap<String, Vec<&'host Host>>;

    fn index(&self, index: &'static str) -> &Self::Output {
        match index {
            "kex_algos" => { &self.kex_algos },
            "host_key_algos" => { &self.host_key_algos },
            "encryption_algos" => { &self.encryption_algos },
            "mac_algos" => { &self.mac_algos },
            "compression_algos" => { &self.compression_algos },
            _ => panic!("Invalid key")
        }
    }
}

pub(crate) fn wrangle_host_to_table(host: &Host) -> Vec<(u16, Option<String>, Vec<Vec<String>>)> {
    let mut res: Vec<(u16, Option<String>, Vec<Vec<String>>)> = Vec::new();
    for port in host.port_states.iter() {
        let mut inner: Vec<Vec<String>> = Vec::with_capacity(5);
        inner.resize_with(5, Default::default);
        let longest = port.algos.longest();
        for i in 0..longest {
            // Weird transpose from
            // A B C
            // X Y Z
            // to
            // A X
            // B Y
            // C Z
            inner.push(vec![
                port.algos.kex_algos.get(i).unwrap_or(&String::new()).to_string(),
                port.algos.host_key_algos.get(i).unwrap_or(&String::new()).to_string(),
                port.algos.encryption_algos.get(i).unwrap_or(&String::new()).to_string(),
                port.algos.mac_algos.get(i).unwrap_or(&String::new()).to_string(),
                port.algos.compression_algos.get(i).unwrap_or(&String::new()).to_string(),
            ]);
        }
        res.push((port.portid, port.product.clone(), inner));
    }
    res
}
