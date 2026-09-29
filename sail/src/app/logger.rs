use std::fs::OpenOptions;
use std::path::Path;
use std::sync::RwLock;

use anyhow::{anyhow, Result};
use tracing::field::Visit;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    filter::{filter_fn, LevelFilter},
    fmt,
    layer::{Layer, Layered},
    prelude::*,
    registry::Registry,
    reload,
    reload::Handle,
};

use crate::config;
use crate::runtime::Host;

type FilterHandle = Handle<LevelFilter, Registry>;

#[derive(Clone, Copy)]
enum LogFormatMode {
    Full,
    Compact,
}

#[derive(Clone, Copy)]
struct LogEventFormat {
    mode: LogFormatMode,
    timestamp: bool,
}

impl<S, N> tracing_subscriber::fmt::format::FormatEvent<S, N> for LogEventFormat
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'writer> tracing_subscriber::fmt::format::FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        match self.mode {
            LogFormatMode::Full if self.timestamp => {
                tracing_subscriber::fmt::format::Format::default().format_event(ctx, writer, event)
            }
            LogFormatMode::Full => tracing_subscriber::fmt::format::Format::default()
                .without_time()
                .format_event(ctx, writer, event),
            LogFormatMode::Compact => {
                struct MessageVisitor {
                    message: Option<String>,
                }

                impl Visit for MessageVisitor {
                    fn record_debug(
                        &mut self,
                        field: &tracing::field::Field,
                        value: &dyn std::fmt::Debug,
                    ) {
                        if field.name() == "message" {
                            self.message = Some(format!("{value:?}"));
                        }
                    }

                    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                        if field.name() == "message" {
                            self.message = Some(value.to_string());
                        }
                    }
                }

                let mut visitor = MessageVisitor { message: None };
                event.record(&mut visitor);

                if self.timestamp {
                    fmt::time::FormatTime::format_time(&fmt::time::SystemTime, &mut writer)?;
                    std::fmt::Write::write_str(&mut writer, " ")?;
                }

                if let Some(mut message) = visitor.message {
                    if message.starts_with('\"') && message.ends_with('\"') && message.len() >= 2 {
                        message = message[1..message.len() - 1].to_string();
                    }
                    std::fmt::Write::write_str(&mut writer, &message)?;
                } else {
                    std::fmt::Write::write_str(&mut writer, "")?;
                }

                std::fmt::Write::write_str(&mut writer, "\n")?;
                Ok(())
            }
        }
    }
}

type WriterLayer = fmt::Layer<
    Layered<reload::Layer<LevelFilter, Registry>, Registry>,
    tracing_subscriber::fmt::format::DefaultFields,
    LogEventFormat,
    tracing_appender::non_blocking::NonBlocking,
>;
type WriterHandle = Handle<WriterLayer, Layered<reload::Layer<LevelFilter, Registry>, Registry>>;

struct HandleController {
    filter: FilterHandle,
    writer: WriterHandle,
    writer_guard: WorkerGuard,
}

impl HandleController {
    pub fn new(filter: FilterHandle, writer: WriterHandle, writer_guard: WorkerGuard) -> Self {
        Self {
            filter,
            writer,
            writer_guard,
        }
    }

    pub fn reload(
        &mut self,
        filter: LevelFilter,
        writer: WriterLayer,
        writer_guard: WorkerGuard,
    ) -> Result<(), reload::Error> {
        self.filter.modify(|f| *f = filter)?;
        self.writer.reload(writer)?;
        self.writer_guard = writer_guard;
        Ok(())
    }
}

static HANDLE: RwLock<Option<HandleController>> = RwLock::new(None);

fn get_writer(config: &config::Log, host: &Host) -> Result<(WriterLayer, WorkerGuard)> {
    let timestamp = config.timestamp;
    let mode = match config.format {
        config::model::LogFormat::Compact => LogFormatMode::Compact,
        config::model::LogFormat::Full => LogFormatMode::Full,
    };

    Ok(match &config.output {
        None if host.log_to_system => {
            let platform = host
                .platform
                .clone()
                .ok_or_else(|| anyhow!("log_to_system: the host provides no system log"))?;
            let (writer, writer_guard) =
                tracing_appender::non_blocking(crate::runtime::platform::LineWriter::new(platform));
            let writer = fmt::Layer::default()
                .with_ansi(false)
                .with_writer(writer)
                .event_format(LogEventFormat { mode, timestamp });
            (writer, writer_guard)
        }
        None => {
            let (writer, writer_guard) = tracing_appender::non_blocking(std::io::stdout());
            let writer = fmt::Layer::default()
                .with_writer(writer)
                .event_format(LogEventFormat { mode, timestamp });
            (writer, writer_guard)
        }
        Some(output_file) => {
            let p = Path::new(output_file);
            let writer = OpenOptions::new().append(true).create(true).open(p)?;
            let (writer, writer_guard) = tracing_appender::non_blocking(writer);
            let writer = fmt::Layer::default()
                .with_ansi(false)
                .with_writer(writer)
                .event_format(LogEventFormat { mode, timestamp });
            (writer, writer_guard)
        }
    })
}

/// Sets up logging as `config` says; `host` may send console output to the
/// system log instead of standard output.
pub fn setup_logger(config: &config::Log, host: &Host) -> Result<()> {
    use config::model::LogLevel;
    // Installed even when disabled, so that a reload can turn it back on,
    // and one that disables it takes effect.
    let filter = match config.level {
        _ if config.disabled => LevelFilter::OFF,
        LogLevel::Trace => LevelFilter::TRACE,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Error | LogLevel::Fatal | LogLevel::Panic => LevelFilter::ERROR,
    };
    let (writer, writer_guard) = get_writer(config, host)?;
    let mut h = HANDLE.write().unwrap_or_else(|e| e.into_inner());
    if let Some(h) = h.as_mut() {
        h.reload(filter, writer, writer_guard)?;
    } else {
        let (filter, filter_handle) = reload::Layer::new(filter);
        let (writer, writer_handle) = reload::Layer::new(writer);
        let sail_filter = filter_fn(|metadata| metadata.target().starts_with("sail"));
        tracing_subscriber::registry()
            .with(filter)
            .with(writer.with_filter(sail_filter))
            .with(
                Broadcast.with_filter(filter_fn(|metadata| metadata.target().starts_with("sail"))),
            )
            .init();
        *h = Some(HandleController::new(
            filter_handle,
            writer_handle,
            writer_guard,
        ));
    }
    Ok(())
}

/// A log line, as those who follow the logs get it.
#[derive(Debug, Clone)]
pub struct LogLine {
    pub level: tracing::Level,
    pub message: String,
}

/// The log lines, to those who follow them (the Clash API's `/logs`).
fn log_lines() -> &'static tokio::sync::broadcast::Sender<std::sync::Arc<LogLine>> {
    static LINES: std::sync::OnceLock<tokio::sync::broadcast::Sender<std::sync::Arc<LogLine>>> =
        std::sync::OnceLock::new();
    // Those who fall this far behind miss lines, rather than hold them.
    LINES.get_or_init(|| tokio::sync::broadcast::channel(256).0)
}

/// Follows the log lines from now on, at the level they are logged.
pub fn follow() -> tokio::sync::broadcast::Receiver<std::sync::Arc<LogLine>> {
    log_lines().subscribe()
}

/// Sends each event to those who follow the logs; with none, nothing is
/// formatted.
struct Broadcast;

impl<S: tracing::Subscriber> Layer<S> for Broadcast {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let lines = log_lines();
        if lines.receiver_count() == 0 {
            return;
        }
        struct Fields(String);
        impl Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if !self.0.is_empty() {
                    self.0.push(' ');
                }
                if field.name() == "message" {
                    self.0.push_str(&format!("{:?}", value));
                } else {
                    self.0.push_str(&format!("{}={:?}", field.name(), value));
                }
            }

            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if !self.0.is_empty() {
                    self.0.push(' ');
                }
                if field.name() == "message" {
                    self.0.push_str(value);
                } else {
                    self.0.push_str(&format!("{}={}", field.name(), value));
                }
            }
        }
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        let _ = lines.send(std::sync::Arc::new(LogLine {
            level: *event.metadata().level(),
            message: fields.0,
        }));
    }
}

/// Sets the level logs are kept at, as the Clash API sets it; none keeps
/// none. A reload sets the configuration's again.
pub fn set_level(level: Option<config::model::LogLevel>) {
    use config::model::LogLevel;
    let filter = match level {
        None => LevelFilter::OFF,
        Some(LogLevel::Trace) => LevelFilter::TRACE,
        Some(LogLevel::Debug) => LevelFilter::DEBUG,
        Some(LogLevel::Info) => LevelFilter::INFO,
        Some(LogLevel::Warn) => LevelFilter::WARN,
        Some(LogLevel::Error | LogLevel::Fatal | LogLevel::Panic) => LevelFilter::ERROR,
    };
    if let Some(h) = HANDLE.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
        let _ = h.filter.modify(|f| *f = filter);
    }
}
