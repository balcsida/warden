//! Audit events. Structured, never containing credentials, shipped asynchronously
//! over OTLP logs (or printed as JSON lines). Emission never blocks the launch.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub name: &'static str,
    pub attrs: BTreeMap<String, String>,
}

impl Event {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            attrs: BTreeMap::new(),
        }
    }
    pub fn attr(mut self, k: &str, v: impl ToString) -> Self {
        self.attrs.insert(k.into(), v.to_string());
        self
    }
}

pub trait AuditSink: Send + Sync {
    fn emit(&self, event: Event);
    /// Bounded; drops whatever has not shipped by then.
    fn flush(&self, timeout: Duration);
}

pub struct Null;
impl AuditSink for Null {
    fn emit(&self, _: Event) {}
    fn flush(&self, _: Duration) {}
}

/// JSON lines on stderr; for `--audit stderr` and debugging.
pub struct Stderr;
impl AuditSink for Stderr {
    fn emit(&self, event: Event) {
        eprintln!(
            "{}",
            serde_json::to_string(&event).expect("event is serialisable")
        );
    }
    fn flush(&self, _: Duration) {}
}

#[cfg(feature = "otlp")]
pub mod otlp {
    use super::*;
    use opentelemetry::logs::{AnyValue, LogRecord, Logger, LoggerProvider, Severity};
    use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig};
    use opentelemetry_sdk::logs::SdkLoggerProvider;

    pub struct Otlp {
        provider: SdkLoggerProvider,
        logger: opentelemetry_sdk::logs::SdkLogger,
    }

    impl Otlp {
        /// HTTP/protobuf exporter with a batch processor on its own thread.
        pub fn new(endpoint: &str, headers: &BTreeMap<String, String>) -> Result<Self, String> {
            let exporter = opentelemetry_otlp::LogExporter::builder()
                .with_http()
                .with_protocol(Protocol::HttpBinary)
                .with_endpoint(endpoint)
                .with_timeout(Duration::from_secs(3))
                .with_headers(
                    headers
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                )
                .build()
                .map_err(|e| e.to_string())?;
            let provider = SdkLoggerProvider::builder()
                .with_resource(
                    opentelemetry_sdk::Resource::builder()
                        .with_service_name("warden")
                        .with_attribute(opentelemetry::KeyValue::new(
                            "service.version",
                            env!("CARGO_PKG_VERSION"),
                        ))
                        .build(),
                )
                .with_batch_exporter(exporter)
                .build();
            let logger = provider.logger("warden");
            Ok(Self { provider, logger })
        }
    }

    impl AuditSink for Otlp {
        fn emit(&self, event: Event) {
            let mut rec = self.logger.create_log_record();
            rec.set_event_name(event.name);
            rec.set_severity_number(Severity::Info);
            rec.set_severity_text("INFO");
            rec.set_body(AnyValue::from(event.name));
            for (k, v) in event.attrs {
                rec.add_attribute(k, v);
            }
            self.logger.emit(rec);
        }
        fn flush(&self, timeout: Duration) {
            let _ = self.provider.force_flush();
            let _ = self.provider.shutdown_with_timeout(timeout);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_json_shape() {
        let e = Event::new("harness.launch")
            .attr("harness", "pi")
            .attr("pid", 42);
        let v: serde_json::Value = serde_json::to_value(&e).unwrap();
        assert_eq!(v["name"], "harness.launch");
        assert_eq!(v["attrs"]["pid"], "42");
    }
}
