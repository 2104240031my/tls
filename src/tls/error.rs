#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {

    // general
    Unknown,
    IllegalArgument,

    // specific
    UnsupportedAlgorithm,
    BufferLengthIncorrect,
    BufferLengthIsNotMultipleOfBlockSize,
    CounterOverwrapped,
    VerificationFailed

}

impl ErrorCode {

    fn to_str(&self) -> &str {
        return match self {
            Self::Unknown                              => "unknown",
            Self::IllegalArgument                      => "illegal argument",
            Self::UnsupportedAlgorithm                 => "unsupported algorithm",
            Self::BufferLengthIncorrect                => "buffer length incorrect",
            Self::BufferLengthIsNotMultipleOfBlockSize => "buffer length is not multiple of block size",
            Self::CounterOverwrapped                   => "counter overwrapped",
            Self::VerificationFailed                   => "verification failed"
        };
    }

}

#[derive(Debug)]
pub struct Error {
    err_code: ErrorCode
}

impl Error {

    pub fn new(err_code: ErrorCode) -> Self {
        return Self{ err_code: err_code };
    }

    pub fn err_code(&self) -> ErrorCode {
        return self.err_code;
    }

}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(f, "Error: {}", self.err_code.to_str());
    }
}

impl std::error::Error for Error {}