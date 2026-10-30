//! Synthetic SSE load generator. Only the benchmark fixture understands its stream-group headers.
//! Matches client.py's streams arguments:
//! stress streams COUNT GATEWAY BODY_MB ROUTE CONNECT_LIMIT RAMP_PER_SECOND [CA_FILE]
//! BODY_MB is ignored; ROUTE is proxy or direct. BENCH_DIRECT_ADDR overrides bench.internal:443.
use std::collections::BTreeMap;
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use rustls_pki_types::{CertificateDer, ServerName};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

const SECRET: &str = "benchmark-secret-value-0123456789";
const PLACEHOLDER: &str = "briq_secret_a1b2c3d4e5f6a7b8";
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const WORKER_TIMEOUT: Duration = Duration::from_secs(100);
type Error = Box<dyn std::error::Error + Send + Sync>;

struct Config {
    count: usize,
    gateway: String,
    direct_addr: String,
    direct: bool,
    connect_limit: usize,
    rate: f64,
    group: String,
    tls: TlsConnector,
}

#[derive(Default)]
struct Shared {
    active: usize,
    peak: usize,
    established: usize,
    all_since: Option<Instant>,
    overlap: Duration,
}

struct ActiveStream(Arc<Mutex<Shared>>, usize);
impl ActiveStream {
    fn new(shared: &Arc<Mutex<Shared>>, count: usize) -> Self {
        let mut stats = shared.lock().unwrap();
        stats.active += 1;
        stats.established += 1;
        stats.peak = stats.peak.max(stats.active);
        if stats.active == count {
            stats.all_since = Some(Instant::now());
        }
        Self(shared.clone(), count)
    }
}
impl Drop for ActiveStream {
    fn drop(&mut self) {
        let mut stats = self.0.lock().unwrap();
        if stats.active == self.1
            && let Some(start) = stats.all_since.take()
        {
            stats.overlap += start.elapsed();
        }
        stats.active -= 1;
    }
}

struct Driver(JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Events {
    expected: Vec<u8>,
    pending: Vec<u8>,
    count: usize,
}
impl Events {
    fn new(direct: bool) -> Self {
        Self {
            expected: format!("data: {}\n\n", if direct { SECRET } else { PLACEHOLDER })
                .into_bytes(),
            pending: Vec::new(),
            count: 0,
        }
    }

    fn push(&mut self, data: &[u8]) -> Result<(), Error> {
        for &byte in data {
            self.pending.push(byte);
            if self.pending.len() > self.expected.len() {
                return Err("unexpected or oversized SSE event".into());
            }
            if self.pending.ends_with(b"\n\n") {
                if self.pending == self.expected {
                    self.count += 1;
                    if self.count > 30 {
                        return Err("too many SSE events".into());
                    }
                } else if self.pending != b": waiting\n\n" || self.count == 0 {
                    return Err("SSE event was not correctly rewritten".into());
                }
                self.pending.clear();
            }
        }
        Ok(())
    }

    fn finish(&self) -> Result<(), Error> {
        if self.count != 30 || !self.pending.is_empty() {
            return Err(format!("incomplete SSE stream: {}/30 events", self.count).into());
        }
        Ok(())
    }
}

struct Stages {
    current: &'static str,
    since: Instant,
    elapsed: BTreeMap<&'static str, f64>,
}
impl Stages {
    fn new() -> Self {
        Self {
            current: "ramp_delay",
            since: Instant::now(),
            elapsed: BTreeMap::new(),
        }
    }
    fn next(&mut self, name: &'static str) {
        self.elapsed
            .insert(self.current, self.since.elapsed().as_secs_f64() * 1000.0);
        self.current = name;
        self.since = Instant::now();
    }
}

struct Report {
    error: Option<String>,
    ttft: Option<f64>,
    stages: BTreeMap<&'static str, f64>,
}

async fn proxy_connect(socket: &mut TcpStream) -> Result<(), Error> {
    socket
        .write_all(b"CONNECT bench.internal:443 HTTP/1.1\r\nHost: bench.internal:443\r\n\r\n")
        .await?;
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = socket.read(&mut buf).await?;
        if n == 0 {
            return Err("proxy closed before CONNECT response".into());
        }
        head.extend_from_slice(&buf[..n]);
        if head.len() > 64 * 1024 {
            return Err("CONNECT response headers too large".into());
        }
        if head.windows(4).any(|s| s == b"\r\n\r\n") {
            if !head.ends_with(b"\r\n\r\n") || !head.starts_with(b"HTTP/1.1 200 ") {
                return Err("CONNECT did not return an empty 200 response".into());
            }
            return Ok(());
        }
    }
}

async fn worker(
    index: usize,
    cfg: Arc<Config>,
    slots: Arc<Semaphore>,
    shared: Arc<Mutex<Shared>>,
) -> Report {
    let mut stages = Stages::new();
    let mut ttft = None;
    let work = async {
        if cfg.rate > 0.0 {
            tokio::time::sleep(Duration::from_secs_f64(index as f64 / cfg.rate)).await;
        }
        stages.next("queued");
        let started = Instant::now();
        let mut setup = Some(slots.acquire_owned().await?);
        stages.next("tcp_connect");
        let mut socket = if cfg.direct {
            tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(&cfg.direct_addr)).await??
        } else {
            tokio::time::timeout(IO_TIMEOUT, TcpStream::connect((cfg.gateway.as_str(), 3128)))
                .await??
        };
        socket.set_nodelay(true)?;
        if !cfg.direct {
            stages.next("connect_response");
            tokio::time::timeout(IO_TIMEOUT, proxy_connect(&mut socket)).await??;
        }
        stages.next("tls_handshake");
        let tls = tokio::time::timeout(
            IO_TIMEOUT,
            cfg.tls
                .connect(ServerName::try_from("bench.internal")?, socket),
        )
        .await??;
        stages.next("response_headers");
        let (mut sender, connection) = tokio::time::timeout(
            IO_TIMEOUT,
            hyper::client::conn::http1::Builder::new()
                .max_buf_size(64 * 1024)
                .handshake(TokioIo::new(tls)),
        )
        .await??;
        let _driver = Driver(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let req = Request::builder()
            .uri("/stream")
            .header("host", "bench.internal:443")
            .header(
                "authorization",
                if cfg.direct { SECRET } else { PLACEHOLDER },
            )
            .header("x-benchmark-stream-group", &cfg.group)
            .header("x-benchmark-stream-count", cfg.count.to_string())
            .body(Empty::<Bytes>::new())?;
        let response = tokio::time::timeout(IO_TIMEOUT, sender.send_request(req)).await??;
        if response.status() != StatusCode::OK {
            return Err(format!("unexpected HTTP status {}", response.status()).into());
        }
        if !cfg.direct
            && response.headers().values().any(|v| {
                v.as_bytes()
                    .windows(SECRET.len())
                    .any(|w| w == SECRET.as_bytes())
            })
        {
            return Err("response header exposed the synthetic secret".into());
        }
        stages.next("first_event");
        let mut body = response.into_body();
        let mut events = Events::new(cfg.direct);
        let mut active = None;
        while let Some(frame) = tokio::time::timeout(IO_TIMEOUT, body.frame()).await? {
            let frame = frame?;
            if let Ok(data) = frame.into_data() {
                events.push(&data)?;
                if events.count > 0 && active.is_none() {
                    stages.next("stream_read");
                    ttft = Some(started.elapsed().as_secs_f64() * 1000.0);
                    active = Some(ActiveStream::new(&shared, cfg.count));
                    setup.take();
                }
            }
        }
        events.finish()?;
        stages.next("complete");
        Ok::<(), Error>(())
    };
    let error = match tokio::time::timeout(WORKER_TIMEOUT, work).await {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(format!("{}: {error}", stages.current)),
        Err(_) => Some(format!(
            "{}: worker exceeded {} seconds",
            stages.current,
            WORKER_TIMEOUT.as_secs()
        )),
    };
    Report {
        error,
        ttft,
        stages: stages.elapsed,
    }
}

fn summary(mut values: Vec<f64>) -> Value {
    if values.is_empty() {
        return Value::Null;
    }
    values.sort_by(f64::total_cmp);
    let n = values.len();
    let median = if n.is_multiple_of(2) {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    } else {
        values[n / 2]
    };
    json!({"p50": median, "p95": values[(n * 95 / 100).min(n - 1)], "max": values[n - 1]})
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 || args[1] != "streams" {
        return Err("usage: stress streams COUNT GATEWAY BODY_MB ROUTE CONNECT_LIMIT RAMP_PER_SECOND [CA_FILE]".into());
    }
    let count: usize = args[2].parse()?;
    let route = args.get(5).map(String::as_str).unwrap_or("proxy");
    let limit: usize = args.get(6).map(String::as_str).unwrap_or("16").parse()?;
    let rate: f64 = args.get(7).map(String::as_str).unwrap_or("50").parse()?;
    if count == 0
        || count > 10000
        || !matches!(route, "direct" | "proxy")
        || !rate.is_finite()
        || rate < 0.0
    {
        return Err("invalid benchmark arguments".into());
    }
    let direct = route == "direct";
    let ca = args.get(8).map(String::as_str).unwrap_or(if direct {
        "/tmp/bench-ca.pem"
    } else {
        "/tmp/gateway-ca.pem"
    });
    let mut roots = rustls::RootCertStore::empty();
    for cert in pem::parse_many(std::fs::read(ca)?)? {
        if cert.tag() == "CERTIFICATE" {
            roots.add(CertificateDer::from(cert.into_contents()))?;
        }
    }
    if roots.is_empty() {
        return Err("CA file contained no certificates".into());
    }
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let cfg = Arc::new(Config {
        count,
        gateway: args[3].clone(),
        direct_addr: env::var("BENCH_DIRECT_ADDR").unwrap_or_else(|_| "bench.internal:443".into()),
        direct,
        connect_limit: if limit == 0 { count } else { limit.min(count) },
        rate,
        group: format!(
            "rust-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ),
        tls: TlsConnector::from(Arc::new(tls)),
    });
    let shared = Arc::new(Mutex::new(Shared::default()));
    let slots = Arc::new(Semaphore::new(cfg.connect_limit));
    let done = Arc::new(AtomicBool::new(false));
    let stop = done.clone();
    let monitor = tokio::spawn(async move {
        let mut lag = Vec::new();
        while !stop.load(Ordering::Relaxed) {
            let start = Instant::now();
            tokio::time::sleep(Duration::from_millis(50)).await;
            lag.push(
                start
                    .elapsed()
                    .saturating_sub(Duration::from_millis(50))
                    .as_secs_f64()
                    * 1000.0,
            );
        }
        lag
    });
    let start = Instant::now();
    let reports = futures_util::future::join_all(
        (0..count).map(|i| tokio::spawn(worker(i, cfg.clone(), slots.clone(), shared.clone()))),
    )
    .await;
    done.store(true, Ordering::Relaxed);
    let lag = monitor.await?;
    let mut completed = 0;
    let mut errors = Vec::new();
    let mut ttft = Vec::new();
    let mut stages: BTreeMap<&str, Vec<f64>> = BTreeMap::new();
    for report in reports {
        match report {
            Ok(report) => {
                if let Some(error) = report.error {
                    errors.push(error);
                } else {
                    completed += 1;
                }
                if let Some(ms) = report.ttft {
                    ttft.push(ms);
                }
                for (stage, ms) in report.stages {
                    stages.entry(stage).or_default().push(ms);
                }
            }
            Err(error) => errors.push(format!("worker task: {error}")),
        }
    }
    let stats = shared.lock().unwrap();
    if stats.peak != count || stats.overlap < Duration::from_secs(5) {
        errors.push(format!(
            "insufficient overlap: peak={}, seconds={:.3}",
            stats.peak,
            stats.overlap.as_secs_f64()
        ));
    }
    let error_count = errors.len();
    let stage_ms: BTreeMap<&str, Value> =
        stages.into_iter().map(|(k, v)| (k, summary(v))).collect();
    println!(
        "{}",
        json!({
            "client": "rust", "mode": "streams", "route": route, "concurrency": count,
            "connect_limit": limit, "ramp_per_second": rate, "established": stats.established,
            "completed": completed, "peak_active_streams": stats.peak, "all_streams_seconds": stats.overlap.as_secs_f64(),
            "seconds": start.elapsed().as_secs_f64(), "ttft_ms": summary(ttft), "stage_ms": stage_ms,
            "runtime_lag_ms": summary(lag), "io_timeout_s": IO_TIMEOUT.as_secs(), "worker_timeout_s": WORKER_TIMEOUT.as_secs(),
            "error_count": error_count, "errors": errors.into_iter().take(5).collect::<Vec<_>>()
        })
    );
    if error_count > 0 || completed != count {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_split_events_and_heartbeats() {
        let mut events = Events::new(false);
        let body = format!(
            "data: {PLACEHOLDER}\n\n: waiting\n\n{}",
            format!("data: {PLACEHOLDER}\n\n").repeat(29)
        );
        for part in body.as_bytes().chunks(7) {
            events.push(part).unwrap();
        }
        events.finish().unwrap();
        assert_eq!(events.count, 30);
    }
    #[test]
    fn rejects_leaks_truncation_and_extra_events() {
        let mut leaked = Events::new(false);
        assert!(
            leaked
                .push(format!("data: {SECRET}\n\n").as_bytes())
                .is_err()
        );
        let mut short = Events::new(false);
        short
            .push(format!("data: {PLACEHOLDER}\n\n").as_bytes())
            .unwrap();
        assert!(short.finish().is_err());
        let mut extra = Events::new(false);
        assert!(
            extra
                .push(format!("data: {PLACEHOLDER}\n\n").repeat(31).as_bytes())
                .is_err()
        );
    }
    #[test]
    fn direct_control_requires_the_expected_synthetic_secret() {
        let mut events = Events::new(true);
        events
            .push(format!("data: {SECRET}\n\n").repeat(30).as_bytes())
            .unwrap();
        events.finish().unwrap();
    }
}
