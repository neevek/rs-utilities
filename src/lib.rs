#[macro_use]
pub mod macros;

pub mod dns;
use std::sync::Once;

extern crate pretty_env_logger;

static INIT_LOGGER_ONCE: Once = Once::new();

#[cfg(not(target_os = "android"))]
macro_rules! colored_log {
    ($buf:ident, $record:ident, $tag:ident, $term_color:literal, $level:literal) => {{
        let filename = $record.file().unwrap_or("unknown");
        let filename = &filename[filename.rfind('/').map(|pos| pos + 1).unwrap_or(0)..];
        writeln!(
            $buf,
            concat!($term_color, "{} [{}] [{}:{}] [", $level, "] {}\x1B[0m"),
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S.%3f"),
            $tag,
            filename,
            $record.line().unwrap_or(0),
            $record.args()
        )
    }};
}

pub struct LogHelper;
impl LogHelper {
    pub fn init_logger(tag: &'static str, log_level: &str) {
        INIT_LOGGER_ONCE.call_once(|| LogHelper::do_init_logger(tag, log_level));
    }

    #[cfg(not(target_os = "android"))]
    fn do_init_logger(tag: &'static str, log_level_str: &str) {
        use std::io::Write;
        let log_level_filter;
        match log_level_str.as_ref() {
            "D" => log_level_filter = log::LevelFilter::Debug,
            "I" => log_level_filter = log::LevelFilter::Info,
            "W" => log_level_filter = log::LevelFilter::Warn,
            "E" => log_level_filter = log::LevelFilter::Error,
            _ => log_level_filter = log::LevelFilter::Trace,
        }

        pretty_env_logger::formatted_timed_builder()
            .format(move |buf, record| match record.level() {
                log::Level::Trace => colored_log!(buf, record, tag, "\x1B[0m", "T"),
                log::Level::Debug => colored_log!(buf, record, tag, "\x1B[92m", "D"),
                log::Level::Info => colored_log!(buf, record, tag, "\x1B[34m", "I"),
                log::Level::Warn => colored_log!(buf, record, tag, "\x1B[93m", "W"),
                log::Level::Error => colored_log!(buf, record, tag, "\x1B[31m", "E"),
            })
            .filter(None, log_level_filter)
            .init();
    }

    #[cfg(target_os = "android")]
    fn do_init_logger(tag: &str, log_level_str: &str) {
        let log_level;
        match log_level_str.as_ref() {
            "D" => log_level = log::Level::Debug,
            "I" => log_level = log::Level::Info,
            "W" => log_level = log::Level::Warn,
            "E" => log_level = log::Level::Error,
            _ => log_level = log::Level::Trace,
        }

        android_logger::init_once(
            android_logger::Config::default()
                .with_min_level(log_level)
                .with_tag(tag),
        );
    }
}

pub struct Utils;

impl Utils {
    pub fn to_u32_be(array: &[u8]) -> u32 {
        if array.len() < 4 {
            panic!("array length is less than 4");
        }
        ((array[0] as u32) << 24)
            + ((array[1] as u32) << 16)
            + ((array[2] as u32) << 8)
            + ((array[3] as u32) << 0)
    }

    pub fn to_u32_le(array: &[u8]) -> u32 {
        if array.len() < 4 {
            panic!("array length is less than 4");
        }
        ((array[0] as u32) << 0)
            + ((array[1] as u32) << 8)
            + ((array[2] as u32) << 16)
            + ((array[3] as u32) << 24)
    }

    pub fn as_u32_be(n: u32, array: &mut [u8]) {
        if array.len() < 4 {
            panic!("array length is less than 4");
        }
        array[0] = ((n >> 24) & 0xff) as u8;
        array[1] = ((n >> 16) & 0xff) as u8;
        array[2] = ((n >> 8) & 0xff) as u8;
        array[3] = (n & 0xff) as u8;
    }

    pub fn as_u32_le(n: u32, array: &mut [u8]) {
        if array.len() < 4 {
            panic!("array length is less than 4");
        }
        array[0] = (n & 0xff) as u8;
        array[1] = ((n >> 8) & 0xff) as u8;
        array[2] = ((n >> 16) & 0xff) as u8;
        array[3] = ((n >> 24) & 0xff) as u8;
    }

    pub fn copy_slice(dst: &mut [u8], src: &[u8]) -> usize {
        let min_len = std::cmp::min(dst.len(), src.len());
        dst[..min_len].copy_from_slice(&src[..min_len]);
        min_len
    }
}

pub struct ByteBuffer<const N: usize> {
    arr: [u8; N],
    used: usize,
}

impl<const N: usize> ByteBuffer<N> {
    pub fn new() -> Self {
        ByteBuffer {
            arr: [0u8; N],
            used: 0,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.arr[..self.used]
    }

    /// return false if remaining buffer is not big enough to store the data
    pub fn append(&mut self, data: &[u8]) -> bool {
        if data.len() + self.used > N {
            return false;
        }
        Utils::copy_slice(&mut self.arr[self.used..], data);
        self.used += data.len();
        true
    }

    pub fn append_byte(&mut self, byte: u8) -> bool {
        if 1 + self.used > N {
            return false;
        }
        self.arr[self.used] = byte;
        self.used += 1;
        true
    }

    pub fn clear(&mut self) {
        self.used = 0;
    }

    pub const fn remaining(&self) -> usize {
        N - self.used
    }

    pub const fn len(&self) -> usize {
        self.used
    }

    pub const fn capacity(&self) -> usize {
        N
    }
}

#[cfg(test)]

mod tests {
    use crate::{LogHelper, Utils};

    #[test]
    fn it_works() {
        LogHelper::init_logger("Test", "T");
        log::trace!("test trace");
        log::debug!("test debug");
        log::info!("test info");
        log::warn!("test warn");
        log::error!("test error");

        let mut arr1 = [0u8; 1024];
        arr1[3] = 1;

        assert_eq!(Utils::to_u32_be(&[0, 0, 0, 1]), 1);
        assert_eq!(Utils::to_u32_le(&[0, 0, 0, 1]), 16777216);
        assert_eq!(Utils::to_u32_be(&arr1[..4]), 1);

        let mut arr2 = [0u8; 1024];
        let n = 0x12345678;
        Utils::as_u32_be(n, &mut arr2);
        assert_eq!(Utils::to_u32_be(&arr2[..4]), n);
        assert_eq!(Utils::to_u32_le(&arr2[..4]), 0x78563412);
    }
}
