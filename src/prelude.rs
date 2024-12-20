use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error in parsing DNS request")]
    ParseError,
}

pub type Result<T> = std::result::Result<T, Error>;