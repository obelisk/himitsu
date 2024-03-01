
pub type HResult<T> = Result<T, HimitsuError>;


#[derive(Debug)]
pub enum HimitsuError {
    IncomingMessageError(String),
    OutgoingMessageError(String),
    IoError(std::io::Error),
}

impl std::fmt::Display for HimitsuError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            HimitsuError::IncomingMessageError(e) => write!(f, "Error parsing incoming message: {}", e),
            HimitsuError::OutgoingMessageError(e) => write!(f, "Error serializing and sending response: {}", e),
            HimitsuError::IoError(e) => write!(f, "IO Error: {}", e),
        }
    }
}

impl From<std::io::Error> for HimitsuError {
    fn from(err: std::io::Error) -> Self {
        HimitsuError::IoError(err)
    }
}