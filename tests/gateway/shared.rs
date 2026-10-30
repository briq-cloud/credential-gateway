use std::convert::Infallible;
use std::io::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use credential_gateway::BoxError;
use credential_gateway::ca::{Ca, Leafs};
use credential_gateway::config::{Api, Config, Resolve};
use credential_gateway::events::Events;
use credential_gateway::proxy::{Gateway, Options};
use http::{HeaderMap, Request, Response, StatusCode};
use http_body::Frame;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;

const SECRET: &str = "real-secret-VALUE-0123456789";
const PLACEHOLDER: &str = "briq_secret_a1b2c3d4e5f6a7b8";
const BODY_SECRET: &str = "body-secret-VALUE-9876543210";
const BODY_PLACEHOLDER: &str = "briq_secret_ffffffffeeeeeeee";
const OTHER_PLACEHOLDER: &str = "briq_secret_0000000011111111";
const OWN_SECRET: &str = "own-secret-VALUE-5555555555";
const OWN_PLACEHOLDER: &str = "briq_secret_abcdefabcdefabcd";

type Body = UnsyncBoxBody<Bytes, BoxError>;

fn full(b: impl Into<Bytes>) -> Body {
    Full::new(b.into()).map_err(|n| match n {}).boxed_unsync()
}

/// Serves `handler` on 127.0.0.1, over TLS when `tls` is given.
async fn serve<F, Fut>(tls: Option<TlsAcceptor>, handler: F) -> u16
where
    F: Fn(Request<Incoming>) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = Response<Body>> + Send + 'static,
{
    serve_observed(tls, Arc::new(SocketCounts::default()), handler).await
}

#[derive(Default)]
struct SocketCounts {
    accepted: AtomicUsize,
    active: AtomicUsize,
}

struct ActiveSocket(Arc<SocketCounts>);
impl Drop for ActiveSocket {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn serve_observed<F, Fut>(
    tls: Option<TlsAcceptor>,
    counts: Arc<SocketCounts>,
    handler: F,
) -> u16
where
    F: Fn(Request<Incoming>) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = Response<Body>> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let (h, tls) = (handler.clone(), tls.clone());
            counts.accepted.fetch_add(1, Ordering::SeqCst);
            counts.active.fetch_add(1, Ordering::SeqCst);
            let active = ActiveSocket(counts.clone());
            tokio::spawn(async move {
                let _active = active;
                let svc = service_fn(move |req| {
                    let h = h.clone();
                    async move { Ok::<_, Infallible>(h(req).await) }
                });
                match tls {
                    Some(tls) => {
                        if let Ok(s) = tls.accept(stream).await {
                            let _ = http1::Builder::new()
                                .serve_connection(TokioIo::new(s), svc)
                                .await;
                        }
                    }
                    None => {
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), svc)
                            .await;
                    }
                }
            });
        }
    });
    port
}

#[derive(Clone)]
struct Received {
    method: String,
    uri: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

/// An HTTPS destination with a CA of its own that echoes what it got, and a few special paths.
struct Destination {
    port: u16,
    sockets: Arc<SocketCounts>,
    ca_pem: PathBuf,
    ca_der: rustls_pki_types::CertificateDer<'static>,
    received: Arc<Mutex<Vec<Received>>>,
    go_on: Arc<Notify>,
}

async fn destination(dir: &Path) -> Destination {
    let ca = Ca::load_or_create(&dir.join("dest-ca"), "destination").unwrap();
    let ca_pem = dir.join("dest-ca.pem");
    std::fs::write(&ca_pem, &ca.cert_pem).unwrap();
    let ca_der = ca.cert_der();
    let leafs = Leafs::new(ca).unwrap();
    let tls = TlsAcceptor::from(leafs.for_host("localhost").unwrap());
    let received = Arc::new(Mutex::new(Vec::new()));
    let go_on = Arc::new(Notify::new());
    let (rec, go) = (received.clone(), go_on.clone());
    let sockets = Arc::new(SocketCounts::default());
    let port = serve_observed(Some(tls), sockets.clone(), move |req: Request<Incoming>| {
        let (rec, go) = (rec.clone(), go.clone());
        async move {
            let (parts, body) = req.into_parts();
            let body = body.collect().await.unwrap().to_bytes().to_vec();
            rec.lock().unwrap().push(Received {
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                headers: parts.headers.clone(),
                body: body.clone(),
            });
            let auth = parts
                .headers
                .get("authorization")
                .map(|v| v.to_str().unwrap().to_string());
            let mut res = Response::builder()
                .header("x-echo-auth", auth.clone().unwrap_or_default())
                .header("content-type", "application/json");
            match parts.uri.path() {
                // Server-sent events: one, then a pause until the test says, then two.
                "/stream" => {
                    let go = go.clone();
                    let frames = futures_util::stream::unfold(0, move |n| {
                        let go = go.clone();
                        async move {
                            match n {
                                0 => Some((
                                    Ok::<_, BoxError>(Frame::data(Bytes::from("data: one\n\n"))),
                                    1,
                                )),
                                1 => {
                                    let _ =
                                        tokio::time::timeout(Duration::from_secs(5), go.notified())
                                            .await;
                                    Some((Ok(Frame::data(Bytes::from("data: two\n\n"))), 2))
                                }
                                _ => None,
                            }
                        }
                    });
                    res.body(StreamBody::new(frames).boxed_unsync()).unwrap()
                }
                "/amplified-header" => res
                    .header("x-expanded", "A".repeat(4096))
                    .body(full("ok"))
                    .unwrap(),
                // An upstream dies while echoing a secret across frames.
                "/broken-stream" => {
                    let go = go.clone();
                    let frames = futures_util::stream::unfold(0, move |state| {
                        let go = go.clone();
                        async move {
                            match state {
                                0 => Some((
                                    Ok(Frame::data(Bytes::from(format!(
                                        "before {}",
                                        &SECRET[..10]
                                    )))),
                                    1,
                                )),
                                1 => {
                                    tokio::time::timeout(Duration::from_secs(5), go.notified())
                                        .await
                                        .unwrap();
                                    Some((Err(BoxError::from("injected upstream reset")), 2))
                                }
                                _ => None,
                            }
                        }
                    });
                    res.body(StreamBody::new(frames).boxed_unsync()).unwrap()
                }
                // The real value echoed across two writes.
                "/split" => {
                    let (a, b) = SECRET.split_at(10);
                    let parts = vec![format!("before {a}"), format!("{b} after")];
                    let frames =
                        futures_util::stream::unfold(parts.into_iter(), |mut it| async move {
                            let next = it.next()?;
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            Some((Ok::<_, BoxError>(Frame::data(Bytes::from(next))), it))
                        });
                    res.body(StreamBody::new(frames).boxed_unsync()).unwrap()
                }
                _ => {
                    let payload = json!({
                        "auth": auth,
                        "body": String::from_utf8_lossy(&body),
                    })
                    .to_string();
                    // A server that compresses whatever the client asked for.
                    if let Some(enc) = parts.headers.get("x-test-encoding") {
                        res = res.header("content-encoding", enc.clone());
                        res.body(full(payload)).unwrap()
                    } else if parts.uri.path() == "/dup-encoding" {
                        // Two Content-Encoding headers, the first one saying there is none.
                        let mut gz = flate2::write::GzEncoder::new(
                            Vec::new(),
                            flate2::Compression::default(),
                        );
                        gz.write_all(payload.as_bytes()).unwrap();
                        res = res
                            .header("content-encoding", "identity")
                            .header("content-encoding", "gzip");
                        res.body(full(gz.finish().unwrap())).unwrap()
                    } else if parts.headers.contains_key("x-test-gzip") {
                        let mut gz = flate2::write::GzEncoder::new(
                            Vec::new(),
                            flate2::Compression::default(),
                        );
                        gz.write_all(payload.as_bytes()).unwrap();
                        res = res.header("content-encoding", "gzip");
                        res.body(full(gz.finish().unwrap())).unwrap()
                    } else {
                        res.body(full(payload)).unwrap()
                    }
                }
            }
        }
    })
    .await;
    Destination {
        port,
        sockets,
        ca_pem,
        ca_der,
        received,
        go_on,
    }
}

/// The API the gateway reads its config from and reports to.
#[derive(Default)]
struct ApiState {
    ca: Mutex<String>,
    events: Mutex<Vec<Value>>,
    configs: AtomicUsize,
    events_down: AtomicBool,
    config_down: AtomicBool,
    config_chunked: AtomicBool,
    config: Mutex<Value>,
}

async fn fake_api(config: Value) -> (String, Arc<ApiState>) {
    let state = Arc::new(ApiState::default());
    *state.config.lock().unwrap() = config;
    let st = state.clone();
    let port = serve(None, move |req: Request<Incoming>| {
        let st = st.clone();
        async move {
            let ok = req.headers().get("authorization").map(|v| v.as_bytes())
                == Some(b"Bearer gw-token");
            let (method, path) = (req.method().clone(), req.uri().path().to_string());
            let body = req.into_body().collect().await.unwrap().to_bytes();
            let status = |s: StatusCode| Response::builder().status(s).body(full("")).unwrap();
            if !ok {
                return status(StatusCode::UNAUTHORIZED);
            }
            match (method.as_str(), path.as_str()) {
                ("PUT", "/internal/credential-gateway/ca") => {
                    let v: Value = serde_json::from_slice(&body).unwrap();
                    *st.ca.lock().unwrap() = v["cert"].as_str().unwrap().to_string();
                    status(StatusCode::NO_CONTENT)
                }
                ("GET", "/internal/credential-gateway/config") => {
                    st.configs.fetch_add(1, Ordering::SeqCst);
                    if st.config_down.load(Ordering::SeqCst) {
                        return status(StatusCode::SERVICE_UNAVAILABLE);
                    }
                    let payload = st.config.lock().unwrap().to_string();
                    if st.config_chunked.load(Ordering::SeqCst) {
                        let frames = futures_util::stream::iter(vec![Ok::<_, BoxError>(
                            Frame::data(Bytes::from(payload)),
                        )]);
                        Response::new(StreamBody::new(frames).boxed_unsync())
                    } else {
                        Response::new(full(payload))
                    }
                }
                ("POST", "/internal/credential-gateway/events") => {
                    if st.events_down.load(Ordering::SeqCst) {
                        return status(StatusCode::BAD_GATEWAY);
                    }
                    let v: Value = serde_json::from_slice(&body).unwrap();
                    st.events
                        .lock()
                        .unwrap()
                        .extend(v["events"].as_array().unwrap().iter().cloned());
                    status(StatusCode::NO_CONTENT)
                }
                _ => status(StatusCode::NOT_FOUND),
            }
        }
    })
    .await;
    (format!("http://127.0.0.1:{port}"), state)
}

fn team_config() -> Value {
    json!({
        "secrets": [
            { "name": "TOKEN", "placeholder": PLACEHOLDER, "value": SECRET, "hosts": ["localhost"], "locations": ["header"] },
            { "name": "BODY", "placeholder": BODY_PLACEHOLDER, "value": BODY_SECRET, "hosts": ["localhost"], "locations": ["header", "body"] },
            // A team secret for the same host that the test briq did not name.
            { "name": "OTHER", "placeholder": OTHER_PLACEHOLDER, "value": "other-secret-VALUE", "hosts": ["localhost"], "locations": ["header"] },
        ],
        "briqs": [{
            "id": "bq_test",
            "host": "localhost",
            "secrets": ["TOKEN", "BODY"],
            // The briq's own secret with hosts: its value, for it alone.
            "own": [{ "name": "OWN", "placeholder": OWN_PLACEHOLDER, "value": OWN_SECRET, "hosts": ["localhost"], "locations": ["header"] }],
        }],
    })
}

fn local() -> Resolve {
    Arc::new(|_| Box::pin(async { Ok(vec!["::1".parse().unwrap(), "127.0.0.1".parse().unwrap()]) }))
}

struct World {
    _dir: tempfile::TempDir,
    dest: Destination,
    api: Arc<ApiState>,
    events: Arc<Events>,
    config: Arc<Config>,
    proxy: u16,
    ca_pem: PathBuf,
}

/// Everything composed as main.rs composes it, the CA in `state` (a new one when empty).
async fn world_with(state: Option<&Path>) -> World {
    world_limits(state, 8, 1024).await
}

async fn world_limits(state: Option<&Path>, held_bodies: usize, max_body: usize) -> World {
    world_options(state, held_bodies, max_body, Duration::from_secs(10)).await
}

async fn world_options(
    state: Option<&Path>,
    held_bodies: usize,
    max_body: usize,
    handshake_timeout: Duration,
) -> World {
    world_admission(
        state,
        held_bodies,
        max_body,
        handshake_timeout,
        1024,
        "127.0.0.1",
    )
    .await
}

async fn world_admission(
    state: Option<&Path>,
    held_bodies: usize,
    max_body: usize,
    handshake_timeout: Duration,
    max_connections: usize,
    listen_address: &str,
) -> World {
    world_resources(
        state,
        held_bodies,
        max_body,
        handshake_timeout,
        max_connections,
        listen_address,
        credential_gateway::budget::DEFAULT_REWRITE_BUDGET,
    )
    .await
}

async fn world_budget(rewrite_budget: usize) -> World {
    world_resources(
        None,
        2,
        1024,
        Duration::from_secs(10),
        128,
        "127.0.0.1",
        rewrite_budget,
    )
    .await
}

async fn world_resources(
    state: Option<&Path>,
    held_bodies: usize,
    max_body: usize,
    handshake_timeout: Duration,
    max_connections: usize,
    listen_address: &str,
    rewrite_budget: usize,
) -> World {
    credential_gateway::log::set_level("off");
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let dest = destination(dir.path()).await;
    let (url, api_state) = fake_api(team_config()).await;
    let ca_dir = dir.path().join("ca");
    if let Some(from) = state {
        std::fs::create_dir_all(&ca_dir).unwrap();
        for f in ["ca.crt", "ca.key"] {
            std::fs::copy(from.join(f), ca_dir.join(f)).unwrap();
        }
    }
    let ca = Ca::load_or_create(&ca_dir, "test team").unwrap();
    let api = Arc::new(Api::new(&url, "gw-token"));
    api.register_ca(&ca.cert_pem).await.unwrap();
    let ca_pem = dir.path().join("ca.pem");
    std::fs::write(&ca_pem, &ca.cert_pem).unwrap();
    let config = Arc::new(Config::new(api.clone(), local(), Duration::from_secs(1)));
    config.refresh().await.unwrap();
    let events = Events::new(api);
    let gw = Gateway::new(
        config.clone(),
        Arc::new(Leafs::new(ca).unwrap()),
        events.clone(),
        Options {
            max_body,
            held_bodies,
            handshake_timeout,
            max_connections,
            rewrite_budget,
            upstream_ca: vec![dest.ca_der.clone()],
            upstream_port: Some(dest.port),
        },
    );
    let listener = TcpListener::bind((listen_address, 0)).await.unwrap();
    let proxy = listener.local_addr().unwrap().port();
    tokio::spawn(gw.serve(listener));
    World {
        _dir: dir,
        dest,
        api: api_state,
        events,
        config,
        proxy,
        ca_pem,
    }
}

async fn world() -> World {
    world_with(None).await
}

impl World {
    async fn curl(&self, args: &[&str]) -> String {
        let proxy = format!("http://127.0.0.1:{}", self.proxy);
        let out = Command::new("curl")
            .args(["-sS", "-x", &proxy])
            .args(args)
            .output()
            .await
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn received(&self) -> Vec<Received> {
        self.dest.received.lock().unwrap().clone()
    }

    fn cacert(&self) -> &str {
        self.ca_pem.to_str().unwrap()
    }
}
