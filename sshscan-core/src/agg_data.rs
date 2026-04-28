use crate::Host;
use std::collections::HashMap;

#[derive(Debug, Default, Clone)]
pub struct AggregatedData<'host> {
    kex: HashMap<String, Vec<&'host Host>>,
    host_key: HashMap<String, Vec<&'host Host>>,
    encryption: HashMap<String, Vec<&'host Host>>,
    mac: HashMap<String, Vec<&'host Host>>,
    compression: HashMap<String, Vec<&'host Host>>,
}

macro_rules! build {
    ($host:expr; $hp:expr; $res:expr; {$($nam:ident) +}) => {
        $(
            for $nam in $hp.algos.$nam.iter() {
                if let Some(existing) = $res.$nam.get_mut($nam) {
                    existing.push($host);
                }
                else {
                    $res.$nam.insert($nam.to_owned(), vec![$host]);
                }
            }
        )*
    };
    ($host:expr; $hp:expr; $res:expr) => {build!($host; $hp; $res; {kex host_key encryption mac compression})};
}

impl<'host> AggregatedData<'host> {
    #[must_use]
    pub fn build_from_hosts(hosts: &'host [Host]) -> Self {
        let mut res = Self::default();
        for host in hosts {
            for host_port in &host.port_states {
                build!(host; host_port; res);
            }
        }
        res
    }
}

impl<'host> std::ops::Index<&'static str> for AggregatedData<'host> {
    type Output = HashMap<String, Vec<&'host Host>>;

    fn index(&self, index: &'static str) -> &Self::Output {
        match index {
            "kex_algos" => { &self.kex },
            "host_key_algos" => { &self.host_key },
            "encryption_algos" => { &self.encryption },
            "mac_algos" => { &self.mac },
            "compression_algos" => { &self.compression },
            _ => panic!("Invalid key")
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HostTableView {
    pub port: u16,
    pub product: Option<String>,
    pub algos: Vec<Vec<String>>,
}

pub(crate) fn wrangle_host_to_table(host: &Host) -> Vec<HostTableView> {
    let mut res: Vec<HostTableView> = Vec::new();
    for port in &host.port_states {
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
                port.algos.kex.get(i).unwrap_or(&String::new()).clone(),
                port.algos.host_key.get(i).unwrap_or(&String::new()).clone(),
                port.algos.encryption.get(i).unwrap_or(&String::new()).clone(),
                port.algos.mac.get(i).unwrap_or(&String::new()).clone(),
                port.algos.compression.get(i).unwrap_or(&String::new()).clone(),
            ]);
        }
        res.push(HostTableView { port: port.portid, product: port.product.clone(), algos: inner });
    }
    res
}
