use crate::Host;
use std::collections::HashMap;

#[derive(Debug, Default, Clone)]
pub struct AggregatedData<'host> {
    pub kex_algos: HashMap<String, Vec<&'host Host>>,
    pub host_key_algos: HashMap<String, Vec<&'host Host>>,
    pub encryption_algos: HashMap<String, Vec<&'host Host>>,
    pub mac_algos: HashMap<String, Vec<&'host Host>>,
    pub compression_algos: HashMap<String, Vec<&'host Host>>,
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