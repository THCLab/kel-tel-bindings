use keri::error::Error as KeriError;
use teliox::error::Error as TelError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    DynError(#[from] Box<dyn std::error::Error>),

    #[error(transparent)]
    KeriError(#[from] KeriError),

    #[error(transparent)]
    TelError(#[from] TelError),

    #[error("{0}")]
    Generic(String),
}
