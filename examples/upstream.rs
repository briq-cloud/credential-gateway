//! Benchmark-only TLS upstream, paired with examples/stress.rs and the Python API fixture.
//! Defaults: 0.0.0.0:443, /tmp/cert.pem, /tmp/key.pem. BENCH_TLS_ADDR,
//! BENCH_CERT_PATH and BENCH_KEY_PATH override these for local smoke tests.
use std::collections::HashMap;
use std::convert::Infallible;
use std::env;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body::Frame;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;

const SECRET: &[u8] = b"benchmark-secret-value-0123456789";
const PLACEHOLDER: &[u8] = b"briq_secret_a1b2c3d4e5f6a7b8";
const EVENT: &[u8] = b"data: benchmark-secret-value-0123456789\n\n";
const HEARTBEAT: &[u8] = b": waiting\n\n";
type Error = Box<dyn std::error::Error + Send + Sync>;
type Body = UnsyncBoxBody<Bytes, Error>;
type Groups = Arc<Mutex<HashMap<String, Arc<Group>>>>;

struct Group {
    target: usize,
    arrived: AtomicUsize,
    ready: watch::Sender<bool>,
}

struct Lease {
    key: String,
    group: Arc<Group>,
    groups: Groups,
}
impl Lease {
    fn arrive(&self) {
        if self.group.arrived.fetch_add(1, Ordering::SeqCst) + 1 == self.group.target {
            self.group.ready.send_replace(true);
            self.remove();
        }
    }
    fn remove(&self) {
        let mut groups = self.groups.lock().unwrap();
        if groups
            .get(&self.key)
            .is_some_and(|group| Arc::ptr_eq(group, &self.group))
        {
            groups.remove(&self.key);
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.remove();
    }
}

fn group(headers: &HeaderMap, groups: &Groups) -> Result<Lease, Error> {
    let key = headers
        .get("x-benchmark-stream-group")
        .map(|v| v.to_str())
        .transpose()?
        .unwrap_or("");
    let count: usize = headers
        .get("x-benchmark-stream-count")
        .map(|v| v.to_str())
        .transpose()?
        .unwrap_or("1")
        .parse()?;
    if !(1..=10000).contains(&count) || (count > 1 && key.is_empty()) || key.len() > 128 {
        return Err("invalid stream group".into());
    }
    // Ungrouped requests always form an independent, immediately ready stream.
    let group = if count == 1 {
        Arc::new(Group {
            target: 1,
            arrived: AtomicUsize::new(0),
            ready: watch::channel(false).0,
        })
    } else {
        let mut entries = groups.lock().unwrap();
        let group = entries
            .entry(key.to_owned())
            .or_insert_with(|| {
                Arc::new(Group {
                    target: count,
                    arrived: AtomicUsize::new(0),
                    ready: watch::channel(false).0,
                })
            })
            .clone();
        if group.target != count {
            return Err("inconsistent stream group size".into());
        }
        group
    };
    Ok(Lease {
        key: key.to_owned(),
        group,
        groups: groups.clone(),
    })
}

struct Sse {
    lease: Lease,
    ready: watch::Receiver<bool>,
    emitted: usize,
    joined: bool,
    deadline: Instant,
    finished: bool,
}

fn sse(lease: Lease) -> Body {
    let state = Sse {
        ready: lease.group.ready.subscribe(),
        lease,
        emitted: 0,
        joined: false,
        deadline: Instant::now() + Duration::from_secs(60),
        finished: false,
    };
    let frames = futures_util::stream::unfold(state, |mut state| async move {
        if state.finished {
            return None;
        }
        if state.emitted == 0 {
            state.emitted = 1;
            state.deadline = Instant::now() + Duration::from_secs(60);
            return Some((
                Ok::<_, Error>(Frame::data(Bytes::from_static(EVENT))),
                state,
            ));
        }
        if !state.joined {
            state.lease.arrive();
            state.joined = true;
        }
        while !*state.ready.borrow() {
            let wake = (Instant::now() + Duration::from_secs(1)).min(state.deadline);
            match tokio::time::timeout_at(wake, state.ready.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    state.finished = true;
                    return Some((Err("stream group closed".into()), state));
                }
                Err(_) if Instant::now() >= state.deadline => {
                    state.finished = true;
                    return Some((
                        Err("stream group did not reach its target in 60 seconds".into()),
                        state,
                    ));
                }
                Err(_) => return Some((Ok(Frame::data(Bytes::from_static(HEARTBEAT))), state)),
            }
        }
        // Like the Python fixture: wait one second after every event, including the last.
        tokio::time::sleep(Duration::from_secs(1)).await;
        if state.emitted == 30 {
            return None;
        }
        state.emitted += 1;
        Some((Ok(Frame::data(Bytes::from_static(EVENT))), state))
    });
    StreamBody::new(frames).boxed_unsync()
}

struct Validator {
    expected: usize,
    received: usize,
}
impl Validator {
    fn new(original: usize) -> Result<Self, Error> {
        let expected = original
            .checked_sub(PLACEHOLDER.len())
            .and_then(|n| n.checked_add(SECRET.len()))
            .ok_or("invalid benchmark body length")?;
        Ok(Self {
            expected,
            received: 0,
        })
    }
    fn push(&mut self, data: &[u8]) -> Result<(), Error> {
        let prefix = data.len().min(SECRET.len().saturating_sub(self.received));
        if prefix > 0 && data[..prefix] != SECRET[self.received..self.received + prefix] {
            return Err("body prefix was not rewritten".into());
        }
        if !data[prefix..].iter().all(|&b| b == b'x') {
            return Err("body content changed or retained a placeholder".into());
        }
        self.received = self
            .received
            .checked_add(data.len())
            .ok_or("body size overflow")?;
        if self.received > self.expected {
            return Err("rewritten body is too long".into());
        }
        Ok(())
    }
    fn finish(&self) -> Result<(), Error> {
        if self.received != self.expected {
            return Err("rewritten body is incomplete".into());
        }
        Ok(())
    }
}

fn full(status: StatusCode, body: &'static [u8]) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(
            Full::new(Bytes::from_static(body))
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .unwrap()
}

async fn request(req: Request<Incoming>, groups: Groups) -> Result<Response<Body>, Error> {
    let (parts, mut body) = req.into_parts();
    if parts.headers.get("authorization").map(|v| v.as_bytes()) != Some(SECRET) {
        return Ok(full(
            StatusCode::FORBIDDEN,
            b"synthetic secret was not injected\n",
        ));
    }
    let mut validator = if parts.method == Method::POST && parts.uri.path() == "/echo" {
        let original = parts
            .headers
            .get("x-benchmark-body-length")
            .ok_or("missing original body length")?
            .to_str()?
            .parse()?;
        Some(Validator::new(original)?)
    } else {
        None
    };
    let mut ignored = 0usize;
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame?.into_data() {
            for piece in data.chunks(64 * 1024) {
                if let Some(validator) = &mut validator {
                    validator.push(piece)?;
                } else {
                    ignored = ignored
                        .checked_add(piece.len())
                        .ok_or("body size overflow")?;
                    if ignored > 1024 * 1024 {
                        return Err("unexpected fixture request body".into());
                    }
                }
                tokio::task::yield_now().await;
            }
        }
    }
    if let Some(validator) = validator {
        validator.finish()?;
    }
    if parts.uri.path() == "/stream" {
        let lease = group(&parts.headers, &groups)?;
        return Ok(Response::builder()
            .header("content-type", "text/event-stream")
            .body(sse(lease))?);
    }
    Ok(full(StatusCode::OK, EVENT))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cert_path = env::var("BENCH_CERT_PATH").unwrap_or_else(|_| "/tmp/cert.pem".into());
    let key_path = env::var("BENCH_KEY_PATH").unwrap_or_else(|_| "/tmp/key.pem".into());
    let certs: Vec<CertificateDer<'static>> = pem::parse_many(std::fs::read(cert_path)?)?
        .into_iter()
        .filter(|p| p.tag() == "CERTIFICATE")
        .map(|p| CertificateDer::from(p.into_contents()))
        .collect();
    let pem = pem::parse(std::fs::read(key_path)?)?;
    let key = match pem.tag() {
        "PRIVATE KEY" => PrivateKeyDer::Pkcs8(pem.into_contents().into()),
        "RSA PRIVATE KEY" => PrivateKeyDer::Pkcs1(pem.into_contents().into()),
        "EC PRIVATE KEY" => PrivateKeyDer::Sec1(pem.into_contents().into()),
        _ => return Err("unsupported fixture private key".into()),
    };
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let listener =
        TcpListener::bind(env::var("BENCH_TLS_ADDR").unwrap_or_else(|_| "0.0.0.0:443".into()))
            .await?;
    println!(
        "{}",
        serde_json::json!({"kind":"benchmark_tls_ready", "address":listener.local_addr()?.to_string(), "pid":std::process::id()})
    );
    let groups: Groups = Arc::new(Mutex::new(HashMap::new()));
    loop {
        let (socket, _) = listener.accept().await?;
        socket.set_nodelay(true)?;
        let (acceptor, groups) = (acceptor.clone(), groups.clone());
        tokio::spawn(async move {
            let Ok(Ok(tls)) =
                tokio::time::timeout(Duration::from_secs(10), acceptor.accept(socket)).await
            else {
                return;
            };
            let svc = service_fn(move |req| {
                let groups = groups.clone();
                async move {
                    Ok::<_, Infallible>(match request(req, groups).await {
                        Ok(response) => response,
                        Err(error) => {
                            eprintln!("fixture request failed: {error}");
                            full(StatusCode::BAD_REQUEST, b"invalid benchmark request\n")
                        }
                    })
                }
            });
            let _ = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(60))
                .max_buf_size(64 * 1024)
                .serve_connection(TokioIo::new(tls), svc)
                .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_incremental_body_and_rejects_corruption() {
        let original = 200000;
        let mut data = SECRET.to_vec();
        data.extend(vec![b'x'; original - PLACEHOLDER.len()]);
        let mut validator = Validator::new(original).unwrap();
        for chunk in data.chunks(7) {
            validator.push(chunk).unwrap();
        }
        validator.finish().unwrap();
        let mut short = Validator::new(original).unwrap();
        short.push(&data[..data.len() - 1]).unwrap();
        assert!(short.finish().is_err());
        assert!(Validator::new(original).unwrap().push(b"wrong").is_err());
        let mut long = Validator::new(original).unwrap();
        long.push(&data).unwrap();
        assert!(long.push(b"x").is_err());
    }
    #[tokio::test]
    async fn group_waits_for_every_peer_and_drops_abandoned_entries() {
        let groups: Groups = Arc::new(Mutex::new(HashMap::new()));
        let mut headers = HeaderMap::new();
        headers.insert("x-benchmark-stream-group", "test".parse().unwrap());
        headers.insert("x-benchmark-stream-count", "2".parse().unwrap());
        let first = group(&headers, &groups).unwrap();
        let second = group(&headers, &groups).unwrap();
        first.arrive();
        assert!(!*first.group.ready.borrow());
        second.arrive();
        assert!(*first.group.ready.borrow());
        assert!(groups.lock().unwrap().is_empty());
        let abandoned = group(&headers, &groups).unwrap();
        drop(abandoned);
        assert!(groups.lock().unwrap().is_empty());
    }
}
