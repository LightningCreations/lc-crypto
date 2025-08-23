use super::ErrorKind;

cfg_match::cfg_match! {
    target_os = "linux" => {
        pub fn kind_from_raw_os_error(errno: i32) -> ErrorKind {
            use linux_errno::Error as Errno;
            match errno.try_into().ok().and_then(|v| Errno::new(v)) {
                Some(_) => ErrorKind::__Uncategorized,
                None => ErrorKind::__Internal,
            }
        }
    }
    target_os = "lilium" => {
        pub fn kind_from_raw_os_error(errno: i32) -> ErrorKind {
            match errno as isize {
                _ => ErrorKind::__Uncategorized,
            }
        }
    }
}
