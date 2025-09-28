#[cfg(any(feature = "std", test))]
mod once_impl {
    #[cfg(feature = "__spin")]
    pub type OnceLock<T> = std::sync::OnceLock<T>;

    #[cfg(feature = "__spin")]
    pub fn get_or_init<T>(cell: &OnceLock<T>, f: impl FnOnce() -> T) -> &T {
        cell.get_or_init(f)
    }
}

#[cfg(not(any(feature = "std", test)))]
mod once_impl {
    #[cfg(feature = "__spin")]
    pub type OnceLock<T> = spin::Once<T>;

    #[cfg(feature = "__spin")]
    pub fn get_or_init<T>(cell: &OnceLock<T>, f: impl FnOnce() -> T) -> &T {
        cell.call_once(f)
    }
}

pub use once_impl::*;
