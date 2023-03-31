pub mod xml;
pub mod agg_data;
pub mod html;

use std::num::ParseIntError;
use std::str::FromStr;
use thiserror::Error;


#[derive(Error, Debug)]
pub enum SshScanErr {
    #[error("XML Input malformed")]
    XMLInvalid,
    #[error("Parsing integer failed")]
    ParseIntError(#[from] ParseIntError),
    #[error("Failed to parse XML")]
    XMLParseFailure(#[from] xmltree::ParseError),
}

#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Default, Clone)]
pub struct Host {
    pub status: HostStatus,
    pub addr: String,
    pub port_states: Vec<Description>,
}

#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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
            _ => Self::Unknown,
        })
    }
}

impl Default for HostStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Default, Clone)]
pub struct Description {
    pub portid: u16,
    pub state: bool,
    pub algos: Algos,
}

#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Default, Clone)]
pub struct Algos {
    kex_algos: Vec<String>,
    host_key_algos: Vec<String>,
    encryption_algos: Vec<String>,
    mac_algos: Vec<String>,
    compression_algos: Vec<String>,
}

impl Algos {
    fn longest(&self) -> usize {
        let mut len = 0usize;
        if len < self.kex_algos.len() { len = self.kex_algos.len(); }
        if len < self.host_key_algos.len() { len = self.host_key_algos.len(); }
        if len < self.encryption_algos.len() { len = self.encryption_algos.len(); }
        if len < self.mac_algos.len() { len = self.mac_algos.len(); }
        if len < self.compression_algos.len() { len = self.compression_algos.len(); }
        len
    }
}

impl std::ops::Index<&str> for Algos {
    type Output = Vec<String>;

    fn index(&self, index: &str) -> &Self::Output {
        match index {
            "kex_algorithms" => &self.kex_algos,
            "server_host_key_algorithms" => &self.host_key_algos,
            "encryption_algorithms" => &self.encryption_algos,
            "mac_algorithms" => &self.mac_algos,
            "compression_algorithms" => &self.compression_algos,
            _ => panic!("Invalid index"),
        }
    }
}

impl std::ops::IndexMut<&str> for Algos {
    fn index_mut(&mut self, index: &str) -> &mut Self::Output {
        match index {
            "kex_algorithms" => &mut self.kex_algos,
            "server_host_key_algorithms" => &mut self.host_key_algos,
            "encryption_algorithms" => &mut self.encryption_algos,
            "mac_algorithms" => &mut self.mac_algos,
            "compression_algorithms" => &mut self.compression_algos,
            _ => panic!("Invalid index"),
        }
    }
}