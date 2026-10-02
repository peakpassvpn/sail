use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

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
    /// Its drop writes out the lines queued, and stops the thread that
    /// writes them.
    writer_guard: Option<WorkerGuard>,
}

impl HandleController {
    pub fn new(filter: FilterHandle, writer: WriterHandle, writer_guard: WorkerGuard) -> Self {
        Self {
            filter,
            writer,
            writer_guard: Some(writer_guard),
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
        self.writer_guard = Some(writer_guard);
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

/// Writes out the lines logged so far, before the process exits: a thread
/// of their own writes them, which exiting stops with lines unwritten, and
/// the static that holds it is never dropped. Lines logged after are lost
/// until the logger is set up again.
pub fn flush() {
    let guard = HANDLE
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .as_mut()
        .and_then(|h| h.writer_guard.take());
    drop(guard);
}

/// What `log.redact` leaves out, as bits: the process's, as the level is.
static REDACT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

fn redact_bit(what: config::model::LogRedact) -> u8 {
    use config::model::LogRedact;
    match what {
        LogRedact::Destination => 1,
        LogRedact::Source => 2,
        LogRedact::Process => 4,
    }
}

/// Whether lines at INFO and above leave `what` out.
pub(crate) fn redacts(what: config::model::LogRedact) -> bool {
    REDACT.load(std::sync::atomic::Ordering::Relaxed) & redact_bit(what) != 0
}

/// A destination as a line at INFO or above shows it: `*:443` when
/// destinations are redacted.
pub(crate) fn destination(addr: &crate::session::SocksAddr) -> String {
    if redacts(config::model::LogRedact::Destination) {
        format!("*:{}", addr.port())
    } else {
        addr.to_string()
    }
}

/// A client address or device as a line at INFO or above shows it.
pub(crate) fn source(shown: impl std::fmt::Display) -> String {
    if redacts(config::model::LogRedact::Source) {
        "*".to_string()
    } else {
        shown.to_string()
    }
}

/// Runs `f` with what sail logs on this thread at WARN or above kept,
/// not written out: a check tells them, as a start would log them.
pub(crate) fn collect_warnings<T>(f: impl FnOnce() -> T) -> (T, Vec<String>) {
    struct Collect(Arc<Mutex<Vec<String>>>);
    impl<S: tracing::Subscriber> Layer<S> for Collect {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let meta = event.metadata();
            if *meta.level() > tracing::Level::WARN || !meta.target().starts_with("sail") {
                return;
            }
            let mut fields = Fields(String::new());
            event.record(&mut fields);
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(fields.0);
        }
    }
    let kept = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(Collect(kept.clone()));
    let out = tracing::subscriber::with_default(subscriber, f);
    let kept = std::mem::take(&mut *kept.lock().unwrap_or_else(|e| e.into_inner()));
    (out, kept)
}

/// Sets up logging as `config` says; `host` may send console output to the
/// system log instead of standard output. Logging is the process's: the
/// last instance to start or reload sets its level and output. Where the
/// host installed a subscriber of its own already, sail's is not
/// installed, and logs nothing.
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
    REDACT.store(
        config
            .redact
            .iter()
            .fold(0, |bits, r| bits | redact_bit(*r)),
        std::sync::atomic::Ordering::Relaxed,
    );
    let mut h = HANDLE.write().unwrap_or_else(|e| e.into_inner());
    if let Some(h) = h.as_mut() {
        h.reload(filter, writer, writer_guard)?;
    } else {
        let (filter, filter_handle) = reload::Layer::new(filter);
        let (writer, writer_handle) = reload::Layer::new(writer);
        let sail_filter = filter_fn(|metadata| metadata.target().starts_with("sail"));
        let installed = tracing_subscriber::registry()
            .with(filter)
            .with(writer.with_filter(sail_filter))
            .with(
                Broadcast.with_filter(filter_fn(|metadata| metadata.target().starts_with("sail"))),
            )
            .try_init();
        if installed.is_err() {
            // The host's own; tried again at the next start or reload.
            return Ok(());
        }
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
    pub time: std::time::SystemTime,
}

/// What an instance's log tells those who follow it.
#[derive(Debug, Clone)]
pub enum LogEvent {
    Line(Arc<LogLine>),
    /// The lines kept were cleared.
    Cleared,
}

/// Those who fall this far behind miss lines, rather than hold them.
const FOLLOWERS_BEHIND: usize = 256;

/// An instance's log: the lines logged on its threads, from its start or
/// before, which it keeps the latest of, and those who follow them. The
/// host may give an instance one of its own, to read what a start that
/// failed logged.
pub struct InstanceLog {
    kept: Mutex<VecDeque<Arc<LogLine>>>,
    capacity: usize,
    events: tokio::sync::broadcast::Sender<LogEvent>,
}

impl std::fmt::Debug for InstanceLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InstanceLog(keeps {})", self.capacity)
    }
}

impl InstanceLog {
    /// A log keeping the latest `capacity` lines; none with 0.
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            kept: Mutex::new(VecDeque::new()),
            capacity,
            events: tokio::sync::broadcast::channel(FOLLOWERS_BEHIND).0,
        })
    }

    /// The lines kept, and what comes after them: none missed, none twice.
    pub fn follow(
        &self,
    ) -> (
        Vec<Arc<LogLine>>,
        tokio::sync::broadcast::Receiver<LogEvent>,
    ) {
        let kept = self.kept.lock().unwrap_or_else(|e| e.into_inner());
        (kept.iter().cloned().collect(), self.events.subscribe())
    }

    /// Forgets the lines kept; those who follow are told.
    pub fn clear(&self) {
        let mut kept = self.kept.lock().unwrap_or_else(|e| e.into_inner());
        kept.clear();
        let _ = self.events.send(LogEvent::Cleared);
    }

    fn wanted(&self) -> bool {
        self.capacity > 0 || self.events.receiver_count() > 0
    }

    fn push(&self, line: Arc<LogLine>) {
        let mut kept = self.kept.lock().unwrap_or_else(|e| e.into_inner());
        if self.capacity > 0 {
            if kept.len() == self.capacity {
                kept.pop_front();
            }
            kept.push_back(line.clone());
        }
        let _ = self.events.send(LogEvent::Line(line));
    }
}

/// An instance's log, as the host gives it; equal when the same.
#[derive(Clone)]
pub struct InstanceLogRef(pub Arc<InstanceLog>);

impl std::fmt::Debug for InstanceLogRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl PartialEq for InstanceLogRef {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for InstanceLogRef {}

thread_local! {
    /// The log of the instance whose thread this is.
    static CURRENT: std::cell::RefCell<Option<Arc<InstanceLog>>> =
        const { std::cell::RefCell::new(None) };
}

/// Makes what this thread logs `log`'s, until the guard goes.
pub fn enter(log: Option<Arc<InstanceLog>>) -> LogScope {
    LogScope(Some(CURRENT.with(|c| c.replace(log))))
}

/// The log of the instance whose thread this is, for a thread it starts.
pub fn current() -> Option<Arc<InstanceLog>> {
    CURRENT.with(|c| c.borrow().clone())
}

/// Puts back the log this thread logged to before.
pub struct LogScope(Option<Option<Arc<InstanceLog>>>);

impl Drop for LogScope {
    fn drop(&mut self) {
        if let Some(previous) = self.0.take() {
            CURRENT.with(|c| *c.borrow_mut() = previous);
        }
    }
}

/// A line's message and fields, as one string.
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

/// Sends each event to its instance's log; with no one to tell, nothing
/// is formatted.
struct Broadcast;

impl<S: tracing::Subscriber> Layer<S> for Broadcast {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let Some(log) = current().filter(|log| log.wanted()) else {
            return;
        };
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        log.push(Arc::new(LogLine {
            level: *event.metadata().level(),
            message: fields.0,
            time: std::time::SystemTime::now(),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A check keeps what sail logs at WARN and above on its thread, and
    /// nothing else.
    #[test]
    fn warnings_are_collected_on_the_checking_thread() {
        let (out, kept) = collect_warnings(|| {
            tracing::warn!(target: "sail::check", "a field is ignored");
            tracing::error!(target: "sail::check", "and an error");
            tracing::info!(target: "sail::check", "not a warning");
            tracing::warn!(target: "other", "not sail's");
            std::thread::spawn(|| tracing::warn!(target: "sail::check", "another thread"))
                .join()
                .unwrap();
            7
        });
        assert_eq!(out, 7);
        assert_eq!(kept, ["a field is ignored", "and an error"]);
    }

    fn line(message: &str) -> Arc<LogLine> {
        Arc::new(LogLine {
            level: tracing::Level::INFO,
            message: message.into(),
            time: std::time::SystemTime::now(),
        })
    }

    #[test]
    fn a_log_keeps_the_latest_lines_and_tells_its_followers() {
        let log = InstanceLog::new(2);
        for m in ["a", "b", "c"] {
            log.push(line(m));
        }
        let (kept, mut events) = log.follow();
        let kept: Vec<&str> = kept.iter().map(|l| l.message.as_str()).collect();
        assert_eq!(kept, ["b", "c"]);
        log.push(line("d"));
        log.clear();
        assert!(matches!(events.try_recv(), Ok(LogEvent::Line(l)) if l.message == "d"));
        assert!(matches!(events.try_recv(), Ok(LogEvent::Cleared)));
        assert!(log.follow().0.is_empty());
    }

    #[test]
    fn a_thread_logs_to_the_log_it_entered_until_it_leaves() {
        let log = InstanceLog::new(1);
        assert!(current().is_none());
        {
            let _scope = enter(Some(log.clone()));
            assert!(current().is_some_and(|c| Arc::ptr_eq(&c, &log)));
            let other = InstanceLog::new(1);
            {
                let _inner = enter(Some(other.clone()));
                assert!(current().is_some_and(|c| Arc::ptr_eq(&c, &other)));
            }
            assert!(current().is_some_and(|c| Arc::ptr_eq(&c, &log)));
        }
        assert!(current().is_none());
    }
}
