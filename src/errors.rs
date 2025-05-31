use thiserror::Error;

#[derive(Error, Debug)]
pub enum SpyWardError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("NFQueue error: return code {0}")]
    Nfqueue(i32),

    #[error("NFTables command failed: {0}")]
    NftablesCmd(String),

    #[error("Not running as root; UID is {0}")]
    NotRoot(u32),

    #[error("Bind or initialization failed: {0}")]
    InitFailed(String),

    #[error("Unexpected null pointer")]
    NullPtr,
}
