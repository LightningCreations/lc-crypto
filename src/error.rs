#[cfg(feature = "error-track_caller")]
use core::panic::Location;

/// The Kind of Error
///
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// An Error that does not fall into any other category.
    /// This Error is not used by lc-crypto.
    ///
    /// ## Uncategorized vs. Other
    /// Certain Errors are "Uncategorized"
    Other,
    Unsupported,
    Interrupted,
    TimedOut,
    PermissionDenied,
    InvalidInput,
    OutOfMemory,
    ProviderNotFound,
    UnexpectedEof,
    WriteZero,
    WouldBlock,
    InvalidData,

    #[doc(hidden)]
    __Internal,
    #[doc(hidden)]
    __Uncategorized,
    #[doc(hidden)]
    __UncategorizedUser,
}

mod sys;

impl core::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ErrorKind::Other => f.write_str("Other Error"),
            ErrorKind::Unsupported => f.write_str("Unsupported Operation"),
            ErrorKind::Interrupted => f.write_str("Interrupted"),
            ErrorKind::TimedOut => f.write_str("Timed Out"),
            ErrorKind::PermissionDenied => f.write_str("Permission Denied"),
            ErrorKind::InvalidInput => f.write_str("Invalid Input"),
            ErrorKind::InvalidData => f.write_str("Invalid Data"),
            ErrorKind::OutOfMemory => f.write_str("Out of Memory"),
            ErrorKind::ProviderNotFound => f.write_str("Provider not Found"),
            ErrorKind::UnexpectedEof => f.write_str("Unexpected End of File"),
            ErrorKind::WriteZero => f.write_str("Write returned 0"),
            ErrorKind::WouldBlock => f.write_str("Operation would Block"),
            ErrorKind::__Internal => f.write_str("Internal Error (Please Report a bug)"),
            ErrorKind::__Uncategorized | ErrorKind::__UncategorizedUser => {
                f.write_str("(uncategorized error)")
            }
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

/// The type of errors returned from this library.
///
/// ## Traits
/// The type implements [`core::error::Error`]. This allows converting it to many other error types (including [`std::io::Error`]).
///
#[cfg_attr(
    feature = "std",
    doc = "When the `std` feature is available, [`From<std::io::Error>`] is implemented, as well as the reciprocal impl. Note that like the conversions with [`ErrorKind`], these can be lossy when round-tripped."
)]
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    inner: ErrorInner,
    #[cfg(feature = "error-track_caller")]
    #[allow(dead_code)] // Only used by `Debug`
    error_location: &'static Location<'static>,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.kind.fmt(f)?;

        match &self.inner {
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

pub struct Message<'a>(&'a ErrorInner);

impl<'a> core::fmt::Debug for Message<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            #[cfg(feature = "alloc")]
            ErrorInner::Custom(b) => b.fmt(f),
            ErrorInner::Message(m) => m.fmt(f),
            _ => unreachable!(),
        }
    }
}

impl<'a> core::fmt::Display for Message<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            #[cfg(feature = "alloc")]
            ErrorInner::Custom(b) => b.fmt(f),
            ErrorInner::Message(m) => m.fmt(f),
            _ => unreachable!(),
        }
    }
}

impl Error {
    #[cfg_attr(feature = "error-track_caller", track_caller)]
    fn from_kind_and_payload(kind: ErrorKind, inner: ErrorInner) -> Self {
        Self {
            kind,
            inner,
            #[cfg(feature = "error-track_caller")]
            error_location: Location::caller(),
        }
    }

    /// Constructs a new error with the specified `kind` and the specified `payload`.
    ///
    /// Note that this function allocates (even if the payload is a string).
    /// If you do not need a payload, convert from [`ErrorKind`] instead.
    /// If your payload is a string literal, use [`Error::new_with_message`] instead.
    #[cfg(feature = "alloc")]
    #[cfg_attr(feature = "nightly-docs", doc(cfg(feature = "alloc")))]
    #[cfg_attr(feature = "error-track_caller", track_caller)]
    pub fn new<E: Into<alloc::boxed::Box<dyn core::error::Error + Send + Sync + 'static>>>(
        kind: ErrorKind,
        payload: E,
    ) -> Self {
        Self::from_kind_and_payload(kind, ErrorInner::Custom(payload.into()))
    }

    /// Constructs a new error with the specified `kind` and the specified `msg`.
    #[cfg_attr(feature = "error-track_caller", track_caller)]
    pub fn new_with_message(kind: ErrorKind, msg: &'static str) -> Self {
        Self::from_kind_and_payload(kind, ErrorInner::Message(msg))
    }

    /// Constructs a new error from a raw os error.
    #[cfg_attr(feature = "error-track_caller", track_caller)]
    pub fn from_raw_os_error(errno: i32) -> Self {
        let kind = sys::kind_from_raw_os_error(errno);

        Self::from_kind_and_payload(kind, ErrorInner::OsError(errno))
    }

    /// Constructs a new error with the specified payload that indicates an [`ErrorKind::Other`] error.
    ///
    /// Note that this function allocates (even if the payload is a string).
    /// If you do not need a payload, convert from [`ErrorKind`] instead.
    /// If your payload is a string literal, use [`Error::other_with_message`] instead.
    ///
    /// ## Note
    ///
    /// This function should be used if you do not believe a future [`ErrorKind`] variant will match your error case. If you believe a future error would be better suited, use [`Error::uncategorized`] instead.
    /// If you are a library, it may be considered a breaking change to change from this function to any other [`ErrorKind`] (or to [`Error::uncategorized`])
    #[cfg(feature = "alloc")]
    #[cfg_attr(feature = "nightly-docs", doc(cfg(feature = "alloc")))]
    #[cfg_attr(feature = "error-track_caller", track_caller)]
    pub fn other<E: Into<alloc::boxed::Box<dyn core::error::Error + Send + Sync + 'static>>>(
        e: E,
    ) -> Self {
        Self::from_kind_and_payload(ErrorKind::Other, ErrorInner::Custom(e.into()))
    }

    /// Constructs a new error the specified `msg` that indicates an [`ErrorKind::Other`] error.
    ///
    /// ## Note
    ///
    /// This function should be used if you do not believe a future [`ErrorKind`] variant will match your error case. If you believe a future error would be better suited, use [`Error::uncategorized_with_message`] instead.
    /// If you are a library, it may be considered a breaking change to change from this function to any other [`ErrorKind`] (or to [`Error::uncategorized_with_message`])
    #[cfg_attr(feature = "error-track_caller", track_caller)]
    pub fn other_with_message(msg: &'static str) -> Self {
        Self::from_kind_and_payload(ErrorKind::Other, ErrorInner::Message(msg))
    }

    /// Constructs a new error with the specified payload that indicates a kind that cannot be matched.
    ///
    /// Note that this function allocates (even if the payload is a string).
    /// If you do not need a payload, convert from [`ErrorKind`] instead.
    /// If your payload is a string literal, use [`Error::uncategorized_with_message`] instead.
    #[cfg(feature = "alloc")]
    #[cfg_attr(feature = "nightly-docs", doc(cfg(feature = "alloc")))]
    #[cfg_attr(feature = "error-track_caller", track_caller)]
    pub fn uncategorized<
        E: Into<alloc::boxed::Box<dyn core::error::Error + Send + Sync + 'static>>,
    >(
        e: E,
    ) -> Self {
        Self::from_kind_and_payload(ErrorKind::__UncategorizedUser, ErrorInner::Custom(e.into()))
    }

    /// Constructs a new error the specified `msg` that kindicates a kind that cannot be matched.
    #[cfg_attr(feature = "error-track_caller", track_caller)]
    pub fn uncategorized_with_message(msg: &'static str) -> Self {
        Self::from_kind_and_payload(ErrorKind::__UncategorizedUser, ErrorInner::Message(msg))
    }

    /// Returns the error kind.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Returns the raw OS Error.
    ///
    /// If the function was constructed with [`Error::from_raw_os_error`], returns the input value.
    pub fn raw_os_error(&self) -> Option<i32> {
        match self.inner {
            ErrorInner::OsError(o) => Some(o),
            _ => None,
        }
    }

    /// This returns the inner error, if any.
    ///
    /// If this [`Error`] was constructed using [`Error::new`], [`Error::other`], or [`Error::uncategorized`] it returns the inner error.
    /// If this [`Error`] was constructed using [`Error::new_with_message`], [`Error::other_with_message`], or [`Error::uncategorized_with_message`] it returns a Box that contains the message (but cannot be [`Error::downcast`])
    ///
    /// Otherwise, returns [`None`].
    ///
    #[cfg_attr(
        feature = "std",
        doc = "If the [`Error`] was converted from a [`std::io::Error`], then the inner value is the same as the one from the [`std::io::Error`]"
    )]
    #[cfg(feature = "alloc")]
    #[cfg_attr(all(doc, feature = "nightly-docs"), doc(cfg(feature = "alloc")))]
    pub fn into_inner(
        self,
    ) -> Option<alloc::boxed::Box<dyn core::error::Error + Send + Sync + 'static>> {
        match self.inner {
            ErrorInner::Custom(b) => Some(b),
            ErrorInner::Message(n) => Some(Box::from(n)),
            _ => None,
        }
    }

    /// Attempts to downcast to `E`.
    ///
    /// Returns [`Ok`] if the inner error is of type `E`, and [`Err`] otherwise.
    ///
    #[cfg_attr(
        feature = "alloc",
        doc = "This is the same as downcasting [`Error::into_inner`] except that it unwraps the [`Box`], and returns `self` if that fails"
    )]
    ///
    /// ## Notes
    /// This function is available always, but can never succeed unless the `alloc` feature is enabled.
    /// The [`Error::new_with_message`], [`Error::other_with_message`], and [`Error::uncategorized_with_message`] functions do not produce an error that allows downcasting to succeed.
    pub fn downcast<E: core::error::Error + Send + Sync + 'static>(
        self,
    ) -> core::result::Result<E, Self> {
        match self.inner {
            #[cfg(feature = "alloc")]
            ErrorInner::Custom(n) => match n.downcast() {
                Ok(b) => Ok(*b),
                Err(e) => Err(Self {
                    kind: self.kind,
                    inner: ErrorInner::Custom(e),
                    #[cfg(feature = "error-track_caller")]
                    error_location: self.error_location,
                }),
            },
            _ => Err(self),
        }
    }

    /// Returns the message associated with this [`Error`].
    /// This cannot be downcast to an [`core::error::Error`] type, but can be [`Display`][core::fmt::Display]ed or [`Debug`][core::fmt::Debug]ed.
    ///
    /// Returns [`Some`] only if a message was provided (constructed via one of [`Error::new`], [`Error::other`], [`Error::uncategorized`], [`Error::new_with_message`], [`Error::other_with_message`], [`Error::uncategorized_with_message`])
    pub fn message(&self) -> Option<Message> {
        match &self.inner {
            e @ ErrorInner::Message(_) => Some(Message(e)),
            #[cfg(feature = "alloc")]
            e @ ErrorInner::Custom(_) => Some(Message(e)),
            _ => None,
        }
    }
}

impl From<ErrorKind> for Error {
    #[cfg_attr(feature = "error-track_caller", track_caller)]
    fn from(value: ErrorKind) -> Self {
        Error::from_kind_and_payload(value, ErrorInner::None)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

#[cfg(feature = "std")]
#[cfg_attr(feature = "nightly-docs", doc(cfg(feature = "std")))]
impl From<std::io::ErrorKind> for ErrorKind {
    fn from(value: std::io::ErrorKind) -> Self {
        match value {
            std::io::ErrorKind::PermissionDenied => ErrorKind::PermissionDenied,
            std::io::ErrorKind::InvalidInput => ErrorKind::InvalidInput,
            std::io::ErrorKind::InvalidData => todo!(),
            std::io::ErrorKind::TimedOut => ErrorKind::TimedOut,
            #[cfg(feature = "nightly-std-io_error_more")]
            std::io::ErrorKind::InvalidFilename => ErrorKind::InvalidInput,
            std::io::ErrorKind::ArgumentListTooLong => ErrorKind::InvalidInput,
            std::io::ErrorKind::Interrupted => ErrorKind::Interrupted,
            std::io::ErrorKind::Unsupported => ErrorKind::Unsupported,
            std::io::ErrorKind::UnexpectedEof => ErrorKind::UnexpectedEof,
            std::io::ErrorKind::WriteZero => ErrorKind::WriteZero,
            std::io::ErrorKind::WouldBlock => ErrorKind::WouldBlock,
            std::io::ErrorKind::OutOfMemory => ErrorKind::OutOfMemory,
            std::io::ErrorKind::Other => ErrorKind::Other,
            _ => ErrorKind::__Uncategorized,
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(feature = "nightly-docs", doc(cfg(feature = "std")))]
impl From<std::io::Error> for Error {
    #[cfg_attr(feature = "error-track_caller", track_caller)]
    fn from(value: std::io::Error) -> Self {
        let kind: ErrorKind = value.kind().into();

        if let Some(err) = value.raw_os_error() {
            Self::from_kind_and_payload(kind, ErrorInner::OsError(err))
        } else if let Some(e) = value.into_inner() {
            Self::new(kind, e)
        } else {
            Self::from_kind_and_payload(kind, ErrorInner::None)
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(feature = "nightly-docs", doc(cfg(feature = "std")))]
impl From<ErrorKind> for std::io::ErrorKind {
    fn from(value: ErrorKind) -> Self {
        match value {
            ErrorKind::Unsupported => Self::Unsupported,
            ErrorKind::Interrupted => Self::Interrupted,
            ErrorKind::TimedOut => Self::TimedOut,
            ErrorKind::PermissionDenied => Self::PermissionDenied,
            ErrorKind::InvalidInput => Self::InvalidInput,
            ErrorKind::OutOfMemory => Self::OutOfMemory,
            ErrorKind::ProviderNotFound => Self::NotFound,
            ErrorKind::UnexpectedEof => Self::UnexpectedEof,
            ErrorKind::WriteZero => Self::WriteZero,
            ErrorKind::WouldBlock => Self::WouldBlock,
            ErrorKind::InvalidData => Self::InvalidData,
            ErrorKind::Other
            | ErrorKind::__Internal
            | ErrorKind::__Uncategorized
            | ErrorKind::__UncategorizedUser => Self::Other,
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(feature = "nightly-docs", doc(cfg(feature = "std")))]
impl From<Error> for std::io::Error {
    fn from(value: Error) -> Self {
        let kind: std::io::ErrorKind = value.kind.into();

        if let Some(os_err) = value.raw_os_error() {
            Self::from_raw_os_error(os_err)
        } else if let Some(inner) = value.into_inner() {
            Self::new(kind, inner)
        } else {
            Self::from(kind)
        }
    }
}
