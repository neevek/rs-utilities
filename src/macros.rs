#[macro_export]
macro_rules! log_and_bail {
    ($($args:tt)*) => {
        error!($($args)*);
        bail!(format!($($args)*));
    };
}

#[macro_export]
macro_rules! unwrap_or_continue {
    ($opt:ident) => {
        if let Some(value) = $opt {
            value
        } else {
            continue;
        }
    };
}
