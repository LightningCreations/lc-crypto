#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    Other,
    Unsupported,
    Interrupted,
    TimedOut,
    PermissionDenied,
    InvalidInput,
    OutOfMemory,

    #[doc(hidden)]
    __Uncategorized,
}

impl core::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ErrorKind::Other => f.write_str("Other Error"),
            ErrorKind::Unsupported => f.write_str("Unsupported Operation"),
            ErrorKind::Interrupted => f.write_str("Interrupted"),
            ErrorKind::TimedOut => f.write_str("Timed Out"),
            ErrorKind::PermissionDenied => f.write_str("Permission Denied"),
            ErrorKind::InvalidInput => f.write_str("Invalid Input"),
            ErrorKind::OutOfMemory => f.write_str("Out of Memory"),
            ErrorKind::__Uncategorized => f.write_str("(uncategorized error)"),
        }
    }
}

#[derive(Debug)]
enum ErrorInner {
    None,
    #[cfg(feature = "alloc")]
    Custom(alloc::boxed::Box<dyn core::error::Error + Send + Sync + 'static>),
    Message(&'static str),
    OsError(i32),
}

#[derive(Debug)]
pub struct Error(ErrorKind, ErrorInner);

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)?;

        match &self.1 {
            ErrorInner::None => Ok(()),
            #[cfg(feature = "alloc")]
            ErrorInner::Custom(inner) => {
                f.write_str(": ")?;
                inner.fmt(f)
            }
            ErrorInner::Message(msg) => {
                f.write_str(": ")?;
                f.write_str(msg)
            }
            ErrorInner::OsError(i) => f.write_fmt(format_args!(" (os error {i})")),
        }
    }
}

impl Error {
    #[cfg(feature = "alloc")]
    pub fn new<E: Into<alloc::boxed::Box<dyn core::error::Error + Send + Sync + 'static>>>(
        kind: ErrorKind,
        e: E,
    ) -> Self {
        Self(kind, ErrorInner::Custom(e.into()))
    }

    pub fn new_with_message(kind: ErrorKind, msg: &'static str) -> Self {
        Self(kind, ErrorInner::Message(msg))
    }
}

pub type Result<T> = core::result::Result<T, Error>;
