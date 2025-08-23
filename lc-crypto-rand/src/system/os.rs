use lc_crypto_primitives::rand::CsRand;

use lc_crypto_primitives::error::{Error, ErrorKind};

pub struct OsRandom;

impl CsRand for OsRandom {
    fn next_bytes(&mut self, bytes: &mut [u8]) -> lc_crypto_primitives::error::Result<()> {
        cfg_match::cfg_match! {
            any(unix, windows) =>
                getrandom::fill(bytes).map_err(|e| {
                    if let Some(e) = e.raw_os_error() {
                        Error::from_raw_os_error(e)
                    } else {
                        match e {
                            getrandom::Error::UNSUPPORTED => Error::new_with_message(ErrorKind::Unsupported, "getrandom is not supported on this target"),
                            getrandom::Error::UNEXPECTED | getrandom::Error::ERRNO_NOT_POSITIVE => Error::new_with_message(ErrorKind::__Internal, "getrandom reported an internal error"),
                            e => {
                                #[cfg(feature = "std")]
                                {
                                    Error::new(ErrorKind::__Uncategorized, e)
                                }
                                #[cfg(not(feature = "std"))]
                                {
                                    Error::new_with_message(ErrorKind::__Uncategorized, "getrandom reported other error")
                                }
                            }
                        }
                    }
                }),
            all(target_os = "lilium", not(target_env = "kernel")) => unsafe {
                let res = lilium_sys::sys::rand::
            }
        }
    }
}
