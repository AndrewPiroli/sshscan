pub mod xml;
pub mod agg_data;
pub mod html;

use std::num::ParseIntError;
use thiserror::Error;


#[derive(Error, Debug)]
pub enum SshScanErr {
    #[error("XML Input malformed")]
    XMLInvalid,
    #[error("Parsing integer failed")]
    ParseIntError(#[from] ParseIntError),
    #[error("Failed to parse XML")]
    XMLParseFailure(#[from] xmltree::ParseError),
    #[error("Error: {0}")]
    Other(String),
}

#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Default, Clone)]
pub struct Host {
    pub status: HostStatus,
    pub addr: String,
    pub port_states: Vec<Description>,
}

#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Default)]
pub enum HostStatus {
    Up,
    Down,
    #[default]
    Unknown,
}

impl From<&str> for HostStatus {
    fn from(value: &str) -> Self {
        match (value.eq_ignore_ascii_case("up"), value.eq_ignore_ascii_case("down")) {
            (true, _) => Self::Up,
            (_, true) => Self::Down,
            (false, false) => Self::Unknown,
        }
    }
}

#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Default, Clone)]
pub struct Description {
    pub portid: u16,
    pub state: bool,
    pub algos: Algos,
    pub product: Option<String>,
}

#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Default, Clone)]
pub struct Algos {
    kex: Vec<String>,
    host_key: Vec<String>,
    encryption: Vec<String>,
    mac: Vec<String>,
    compression: Vec<String>,
}

impl Algos {
    const fn longest(&self) -> usize {
        let mut len = 0usize;
        if len < self.kex.len() { len = self.kex.len(); }
        if len < self.host_key.len() { len = self.host_key.len(); }
        if len < self.encryption.len() { len = self.encryption.len(); }
        if len < self.mac.len() { len = self.mac.len(); }
        if len < self.compression.len() { len = self.compression.len(); }
        len
    }
}

impl std::ops::Index<&str> for Algos {
    type Output = Vec<String>;

    fn index(&self, index: &str) -> &Self::Output {
        match index {
            "kex_algorithms" => &self.kex,
            "server_host_key_algorithms" => &self.host_key,
            "encryption_algorithms" => &self.encryption,
            "mac_algorithms" => &self.mac,
            "compression_algorithms" => &self.compression,
            _ => panic!("Invalid index"),
        }
    }
}

impl std::ops::IndexMut<&str> for Algos {
    fn index_mut(&mut self, index: &str) -> &mut Self::Output {
        match index {
            "kex_algorithms" => &mut self.kex,
            "server_host_key_algorithms" => &mut self.host_key,
            "encryption_algorithms" => &mut self.encryption,
            "mac_algorithms" => &mut self.mac,
            "compression_algorithms" => &mut self.compression,
            _ => panic!("Invalid index"),
        }
    }
}