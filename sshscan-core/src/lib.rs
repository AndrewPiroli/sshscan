pub mod xml;

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
}
