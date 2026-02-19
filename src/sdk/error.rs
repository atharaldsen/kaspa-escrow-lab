use std::fmt;

#[derive(Debug)]
pub enum EscrowError {
    ScriptBuild(String),
    Verification(String),
    Rpc(String),
    InsufficientFunds { needed: u64, available: u64 },
    InvalidConfig(String),
}

impl fmt::Display for EscrowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ScriptBuild(e) => write!(f, "script build error: {e}"),
            Self::Verification(e) => write!(f, "verification error: {e}"),
            Self::Rpc(e) => write!(f, "RPC error: {e}"),
            Self::InsufficientFunds { needed, available } => {
                write!(
                    f,
                    "insufficient funds: need {needed} sompi, have {available}"
                )
            }
            Self::InvalidConfig(e) => write!(f, "invalid config: {e}"),
        }
    }
}

impl std::error::Error for EscrowError {}

impl From<kaspa_txscript::script_builder::ScriptBuilderError> for EscrowError {
    fn from(e: kaspa_txscript::script_builder::ScriptBuilderError) -> Self {
        Self::ScriptBuild(format!("{e:?}"))
    }
}
