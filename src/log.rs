//! One JSON line per event on stdout: `ts`, `level`, `message`, then the event's own fields.

use std::io::Write;
use std::sync::atomic::{AtomicU8, Ordering};

use serde_json::{Map, Value};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
    Off = 4,
}

impl Level {
    fn name(self) -> &'static str {
        match self {
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
            Level::Off => "off",
        }
    }
}

static MIN: AtomicU8 = AtomicU8::new(Level::Info as u8);

/// `debug`, `info` (the default), `warn`, `error` or `off`.
pub fn set_level(name: &str) {
    let l = match name {
        "debug" => Level::Debug,
        "warn" => Level::Warn,
        "error" => Level::Error,
        "off" => Level::Off,
        _ => Level::Info,
    };
    MIN.store(l as u8, Ordering::Relaxed);
}

/// Writes the line when `level` is at or above the one set. `fields` is a JSON object.
pub fn log(level: Level, message: &str, fields: Value) {
    if level == Level::Off || (level as u8) < MIN.load(Ordering::Relaxed) {
        return;
    }
    let mut line = Map::new();
    let ts = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default();
    line.insert("ts".into(), Value::String(ts));
    line.insert("level".into(), Value::String(level.name().into()));
    line.insert("message".into(), Value::String(message.into()));
    if let Value::Object(f) = fields {
        line.extend(f);
    }
    let mut out = std::io::stdout().lock();
    let _ = serde_json::to_writer(&mut out, &Value::Object(line));
    let _ = out.write_all(b"\n");
}

#[macro_export]
macro_rules! log {
    ($level:ident, $message:expr) => {
        $crate::log::log($crate::log::Level::$level, $message, serde_json::json!({}))
    };
    ($level:ident, $message:expr, $($fields:tt)+) => {
        $crate::log::log($crate::log::Level::$level, $message, serde_json::json!({ $($fields)+ }))
    };
}
