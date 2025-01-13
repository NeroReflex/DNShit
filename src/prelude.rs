use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error in parsing DNS request")]
    ParseError,

    #[error("Error receiving answer to the forwarded DNS query: {error}")]
    ForwardingError { error: std::io::Error },

    #[error("Error opening an UDP socket: {error}")]
    SocketUDPError { error: std::io::Error },
}

pub type Result<T> = std::result::Result<T, Error>;
