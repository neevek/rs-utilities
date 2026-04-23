#[macro_use]
pub mod macros;
pub mod cached_value;
pub mod dns;
pub mod net;
use std::sync::Once;

#[cfg(not(target_os = "android"))]
use std::fmt;

#[cfg(not(target_os = "android"))]
use tracing::field::Visit;

#[cfg(not(target_os = "android"))]
use tracing_subscriber::{
    fmt::{
        format::{FormatEvent, FormatFields, Writer},
        time::{FormatTime, OffsetTime},
    },
    EnvFilter,
};

#[cfg(not(target_os = "android"))]
use tracing_subscriber::{fmt::FmtContext, registry::LookupSpan};

#[cfg(not(target_os = "android"))]
use time::format_description::OwnedFormatItem;

static INIT_LOGGER_ONCE: Once = Once::new();

#[cfg(not(target_os = "android"))]
struct LogFormat {
    tag: &'static str,
    timer: OffsetTime<OwnedFormatItem>,
    ansi: bool,
}

#[cfg(not(target_os = "android"))]
#[derive(Default)]
struct LogEventData {
    file: Option<String>,
    line: Option<u64>,
    message: Option<String>,
}

#[cfg(not(target_os = "android"))]
impl Visit for LogEventData {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match field.name() {
            "log.file" => self.file = Some(value.to_string()),
            "message" => self.message = Some(value.to_string()),
            _ => {}
        }
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if field.name() == "log.line" {
            self.line = Some(value);
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        if field.name() == "log.line" {
            self.line = Some(value.max(0) as u64);
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        if field.name() == "message" && self.message.is_none() {
            self.message = Some(format!("{value:?}"));
        }
    }
}

#[cfg(not(target_os = "android"))]
fn file_name(path: &str) -> &str {
    let bytes = path.as_bytes();
    for i in (0..bytes.len()).rev() {
        if bytes[i] == b'/' || bytes[i] == b'\\' {
            return &path[i + 1..];
        }
    }
    path
}

#[cfg(not(target_os = "android"))]
impl<S, N> FormatEvent<S, N> for LogFormat
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> fmt::Result {
        let level = *event.metadata().level();
        let (color, short_level) = match level {
            tracing::Level::TRACE => ("\x1B[0m", "T"),
            tracing::Level::DEBUG => ("\x1B[92m", "D"),
            tracing::Level::INFO => ("\x1B[34m", "I"),
            tracing::Level::WARN => ("\x1B[93m", "W"),
            tracing::Level::ERROR => ("\x1B[31m", "E"),
        };

        if self.ansi {
            write!(writer, "{color}")?;
        }

        let is_log = event.metadata().target() == "log";
        let mut data = LogEventData::default();
        if is_log {
            event.record(&mut data);
        }
        let file = if let Some(file) = event.metadata().file() {
            file
        } else {
            data.file.as_deref().unwrap_or_default()
        };
        let file_name = file_name(file);
        let line = event
            .metadata()
            .line()
            .map(|l| l as u64)
            .or(data.line)
            .unwrap_or(0);
        self.timer.format_time(&mut writer)?;
        write!(
            writer,
            " [{}] [{}:{}] [{short_level}] ",
            self.tag, file_name, line
        )?;
        if is_log {
            if let Some(message) = data.message {
                write!(writer, "{message}")?;
            } else {
                ctx.format_fields(writer.by_ref(), event)?;
            }
        } else if let Some(message) = data.message {
            write!(writer, "{message}")?;
        } else {
            ctx.format_fields(writer.by_ref(), event)?;
        }

        if self.ansi {
            write!(writer, "\x1B[0m")?;
        }

        writeln!(writer)
    }
}

pub struct LogHelper;
impl LogHelper {
    pub fn init_logger(tag: &'static str, log_filter: &str) {
        INIT_LOGGER_ONCE.call_once(|| LogHelper::do_init_logger(tag, log_filter));
    }

    #[cfg(not(target_os = "android"))]
    fn do_init_logger(tag: &'static str, log_filter: &str) {
        let filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_filter));
        let offset = time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC);
        let format = time::format_description::parse_owned::<2>(
            "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]",
        )
        .unwrap_or_else(|_| {
            time::format_description::parse_owned::<2>(
                "[year]-[month]-[day]T[hour]:[minute]:[second]Z",
            )
            .unwrap()
        });
        let timer = OffsetTime::new(offset, format);

        let _ = tracing_log::LogTracer::init();
        let ansi = atty::is(atty::Stream::Stdout);
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(ansi)
            .event_format(LogFormat { tag, timer, ansi })
            .try_init()
            .ok();
    }

    #[cfg(target_os = "android")]
    fn do_init_logger(tag: &str, log_filter: &str) {
        let log_filter = if let Ok(log_filter) = std::env::var("RUST_LOG") {
            log_filter
        } else {
            log_filter.to_string()
        };

        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Trace)
                .with_tag(tag)
                .with_filter(
                    android_logger::FilterBuilder::new()
                        .parse(log_filter.as_str())
                        .build(),
                ),
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

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub const fn capacity(&self) -> usize {
        N
    }
}

impl<const N: usize> Default for ByteBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]

mod tests {
    use crate::{LogHelper, Utils};

    #[test]
    fn it_works() {
        LogHelper::init_logger("haha", "rs_utilities=trace");
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
