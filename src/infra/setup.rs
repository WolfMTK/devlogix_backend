use tracing_appender::non_blocking::{NonBlocking, NonBlockingBuilder, WorkerGuard};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, fmt};

use crate::infra::config::AppConfig;

fn create_file_appender(log_path: &str, prefix: &str) -> RollingFileAppender {
    RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix(prefix)
        .filename_suffix("jsonl")
        .build(log_path)
        .unwrap()
}

fn create_non_blocking_writer(appender: RollingFileAppender) -> (NonBlocking, WorkerGuard) {
    NonBlockingBuilder::default()
        .lossy(false)
        .buffered_lines_limit(1)
        .finish(appender)
}

fn create_error_layer<S>(writer: NonBlocking) -> impl Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fmt::layer()
        .json()
        .with_writer(writer)
        .with_filter(filter_fn(|metadata| metadata.level() == &tracing::Level::ERROR))
}

fn create_log_layer<S>(writer: NonBlocking) -> impl Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fmt::layer()
        .json()
        .with_writer(writer)
        .with_filter(filter_fn(|metadata| {
            let level = metadata.level();
            level == &tracing::Level::INFO || level == &tracing::Level::WARN
        }))
}

fn create_console_layer<S>() -> impl Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fmt::layer().with_filter(EnvFilter::new("trace"))
}

pub fn init_tracing(config: &AppConfig) -> (WorkerGuard, WorkerGuard) {
    let log_path = &config.logger.log_path;

    let error_appender = create_file_appender(&log_path, "err_logs");
    let log_appender = create_file_appender(&log_path, "app_logs");

    let (error_writer, error_guard) = create_non_blocking_writer(error_appender);
    let (log_writer, log_guard) = create_non_blocking_writer(log_appender);

    tracing_subscriber::registry()
        .with(create_error_layer(error_writer))
        .with(create_log_layer(log_writer))
        .with(create_console_layer())
        .init();

    (error_guard, log_guard)
}
