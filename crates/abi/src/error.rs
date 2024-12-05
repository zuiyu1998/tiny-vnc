use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    
}

#[derive(Debug, Error)]
pub enum ErrorKind {
    
}

pub type Result<T, E = Error> = core::result::Result<T, E>;
