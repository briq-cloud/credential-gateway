//! The gateway against a fake API and a fake destination, with curl as the client, as a briq's
//! tools would be: the destination gets the real value, the client never does.

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
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let (h, tls) = (handler.clone(), tls.clone());
            tokio::spawn(async move {
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
    let port = serve(Some(tls), move |req: Request<Incoming>| {
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
                    Response::new(full(st.config.lock().unwrap().to_string()))
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
            upstream_ca: vec![dest.ca_der.clone()],
            upstream_port: Some(dest.port),
        },
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
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

#[tokio::test]
async fn registers_its_ca_with_the_api() {
    let w = world().await;
    assert!(w.api.ca.lock().unwrap().contains("BEGIN CERTIFICATE"));
}

#[tokio::test]
async fn swaps_the_placeholder_for_the_real_value_in_a_header_and_back_in_the_response() {
    let w = world().await;
    let auth = format!("Authorization: Bearer {PLACEHOLDER}");
    let out = w
        .curl(&[
            "--cacert",
            w.cacert(),
            "-H",
            &auth,
            "-D",
            "-",
            "https://localhost:443/echo?x=1",
        ])
        .await;
    let got = w.received();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].headers["authorization"], format!("Bearer {SECRET}"));
    assert_eq!(got[0].uri, "/echo?x=1");
    assert_eq!(got[0].headers["accept-encoding"], "identity");
    // The client sees the placeholder, in the header and in the body the destination echoed.
    assert!(
        out.contains(&format!("x-echo-auth: Bearer {PLACEHOLDER}")),
        "{out}"
    );
    assert!(
        out.contains(&format!("\"auth\":\"Bearer {PLACEHOLDER}\"")),
        "{out}"
    );
    assert!(!out.contains(SECRET), "the real value reached the client");
}

#[tokio::test]
async fn puts_in_only_the_secrets_the_briq_named() {
    let w = world().await;
    let auth = format!("Authorization: Bearer {OTHER_PLACEHOLDER}");
    w.curl(&[
        "--cacert",
        w.cacert(),
        "-H",
        &auth,
        "https://localhost:443/other",
    ])
    .await;
    let got = w.received();
    assert_eq!(got.len(), 1);
    assert_eq!(
        got[0].headers["authorization"],
        format!("Bearer {OTHER_PLACEHOLDER}")
    );
}

#[tokio::test]
async fn puts_in_the_briqs_own_secret_and_scrubs_it_from_the_response() {
    let w = world().await;
    let auth = format!("Authorization: Bearer {OWN_PLACEHOLDER}");
    let out = w
        .curl(&[
            "--cacert",
            w.cacert(),
            "-H",
            &auth,
            "-D",
            "-",
            "https://localhost:443/own",
        ])
        .await;
    assert_eq!(
        w.received()[0].headers["authorization"],
        format!("Bearer {OWN_SECRET}")
    );
    assert!(
        out.contains(&format!("x-echo-auth: Bearer {OWN_PLACEHOLDER}")),
        "{out}"
    );
    assert!(
        !out.contains(OWN_SECRET),
        "the real value reached the client"
    );
}

#[tokio::test]
async fn substitutes_in_the_body_only_for_a_secret_that_allows_it() {
    let w = world().await;
    let data = json!({ "a": PLACEHOLDER, "b": BODY_PLACEHOLDER }).to_string();
    w.curl(&[
        "--cacert",
        w.cacert(),
        "-X",
        "POST",
        "-H",
        "content-type: application/json",
        "--data",
        &data,
        "https://localhost:443/post",
    ])
    .await;
    let got = w.received();
    assert_eq!(got.len(), 1);
    let body: Value = serde_json::from_slice(&got[0].body).unwrap();
    assert_eq!(
        body["a"], PLACEHOLDER,
        "a header-only secret is never put in a body"
    );
    assert_eq!(body["b"], BODY_SECRET);
    assert_eq!(
        got[0].headers["content-length"],
        got[0].body.len().to_string()
    );
}

#[tokio::test]
async fn sends_a_request_without_a_body_without_one() {
    let w = world().await;
    w.curl(&["--cacert", w.cacert(), "https://localhost:443/get"])
        .await;
    let got = w.received();
    assert_eq!(got[0].method, "GET");
    assert!(
        !got[0].headers.contains_key("content-length"),
        "{:?}",
        got[0].headers
    );
}

#[tokio::test]
async fn substitutes_in_a_body_larger_than_it_holds_as_it_streams() {
    let w = world().await;
    // Over the 1 KiB the test gateway holds, the placeholder past it and at a chunk's edge.
    let data = format!(
        "{}{BODY_PLACEHOLDER}{}{BODY_PLACEHOLDER}",
        "x".repeat(1500),
        "y".repeat(70_000)
    );
    let file = w._dir.path().join("big.txt");
    std::fs::write(&file, &data).unwrap();
    let at = format!("@{}", file.display());
    w.curl(&[
        "--cacert",
        w.cacert(),
        "-X",
        "POST",
        "--data-binary",
        &at,
        "https://localhost:443/big",
    ])
    .await;
    let got = w.received();
    assert_eq!(got.len(), 1);
    let want = data.replace(BODY_PLACEHOLDER, BODY_SECRET);
    assert_eq!(String::from_utf8_lossy(&got[0].body), want);
}

#[tokio::test]
async fn reads_a_response_that_comes_compressed_anyway() {
    let w = world().await;
    let auth = format!("Authorization: Bearer {PLACEHOLDER}");
    let out = w
        .curl(&[
            "--cacert",
            w.cacert(),
            "--compressed",
            "-H",
            &auth,
            "-H",
            "x-test-gzip: 1",
            "-D",
            "-",
            "https://localhost:443/gz",
        ])
        .await;
    // Decompressed, scrubbed, sent on plain.
    assert!(
        out.contains(&format!("\"auth\":\"Bearer {PLACEHOLDER}\"")),
        "{out}"
    );
    assert!(
        !out.contains(SECRET),
        "the real value reached the client in a compressed body"
    );
    assert!(
        !out.to_ascii_lowercase().contains("content-encoding"),
        "{out}"
    );
}

#[tokio::test]
async fn passes_a_streamed_response_on_as_it_comes() {
    let w = world().await;
    let proxy = format!("http://127.0.0.1:{}", w.proxy);
    let auth = format!("Authorization: Bearer {PLACEHOLDER}");
    let mut child = Command::new("curl")
        .args([
            "-sSN",
            "-x",
            &proxy,
            "--cacert",
            w.cacert(),
            "-H",
            &auth,
            "https://localhost:443/stream",
        ])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    // The first event, while the destination still holds the second.
    let first = tokio::time::timeout(Duration::from_secs(2), lines.next_line()).await;
    assert_eq!(
        first
            .expect("the first event waited for the end")
            .unwrap()
            .unwrap(),
        "data: one"
    );
    w.dest.go_on.notify_one();
    let mut rest = String::new();
    while let Some(l) = lines.next_line().await.unwrap() {
        rest.push_str(&l);
    }
    assert!(rest.contains("data: two"), "{rest}");
    child.wait().await.unwrap();
}

#[tokio::test]
async fn scrubs_a_real_value_split_across_two_writes() {
    let w = world().await;
    let auth = format!("Authorization: Bearer {PLACEHOLDER}");
    let out = w
        .curl(&[
            "--cacert",
            w.cacert(),
            "-H",
            &auth,
            "https://localhost:443/split",
        ])
        .await;
    assert_eq!(out, format!("before {PLACEHOLDER} after"));
}

#[tokio::test]
async fn refuses_a_request_whose_host_is_not_the_connect_host() {
    let w = world().await;
    let auth = format!("Authorization: Bearer {PLACEHOLDER}");
    let out = w
        .curl(&[
            "--cacert",
            w.cacert(),
            "-H",
            "Host: other.example",
            "-H",
            &auth,
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "https://localhost:443/x",
        ])
        .await;
    assert_eq!(out, "400");
    assert!(w.received().is_empty(), "the destination was reached");
}

#[tokio::test]
async fn tunnels_a_host_no_secret_allows_without_touching_the_bytes() {
    let w = world().await;
    let auth = format!("Authorization: Bearer {PLACEHOLDER}");
    let url = format!("https://localhost:{}/tunnel", w.dest.port);
    // The destination's own CA, since the gateway did not terminate anything.
    let out = w
        .curl(&[
            "--cacert",
            w.dest.ca_pem.to_str().unwrap(),
            "-H",
            &auth,
            &url,
        ])
        .await;
    let got = w.received();
    assert_eq!(got.len(), 1);
    assert_eq!(
        got[0].headers["authorization"],
        format!("Bearer {PLACEHOLDER}"),
        "no injection off the allow-list"
    );
    assert!(out.contains(PLACEHOLDER));
}

#[tokio::test]
async fn answers_its_health_check() {
    let w = world().await;
    let out = Command::new("curl")
        .args(["-sS", &format!("http://127.0.0.1:{}/healthz", w.proxy)])
        .output()
        .await
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");
}

#[tokio::test]
async fn reports_which_briq_used_which_secret_against_which_host() {
    let w = world().await;
    let auth = format!("Authorization: Bearer {PLACEHOLDER}");
    w.curl(&[
        "--cacert",
        w.cacert(),
        "-H",
        &auth,
        "https://localhost:443/a",
    ])
    .await;
    w.curl(&[
        "--cacert",
        w.cacert(),
        "-H",
        &auth,
        "https://localhost:443/b",
    ])
    .await;
    w.events.flush().await;
    let posted = w.api.events.lock().unwrap().clone();
    let e = posted
        .iter()
        .find(|e| e["secrets"] == json!(["TOKEN"]))
        .expect("a TOKEN event");
    assert_eq!(e["briqId"], "bq_test");
    assert_eq!(e["host"], "localhost");
    assert_eq!(e["method"], "GET");
    assert_eq!(e["status"], 200);
    assert_eq!(e["count"], 2);
    assert!(e["firstAt"].is_string() && e["lastAt"].is_string());
}

#[tokio::test]
async fn keeps_a_batch_the_api_did_not_take_for_the_next_flush() {
    let w = world().await;
    w.api.events_down.store(true, Ordering::SeqCst);
    w.events.record(
        Some("bq_a"),
        "api.example.com",
        "GET",
        200,
        vec!["K".into()],
    );
    w.events.flush().await;
    assert!(w.api.events.lock().unwrap().is_empty());
    w.events.record(
        Some("bq_a"),
        "api.example.com",
        "GET",
        200,
        vec!["K".into()],
    );
    w.api.events_down.store(false, Ordering::SeqCst);
    w.events.flush().await;
    let posted = w.api.events.lock().unwrap().clone();
    assert_eq!(posted.len(), 1);
    assert_eq!(posted[0]["count"], 2);
}

/// A CA made by the earlier gateway (Node, @peculiar/x509) is read and used as it is.
#[tokio::test]
async fn uses_the_ca_an_earlier_gateway_left_on_the_volume() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/node-ca");
    let w = world_with(Some(&fixture)).await;
    let registered = w.api.ca.lock().unwrap().clone();
    assert_eq!(
        registered,
        std::fs::read_to_string(fixture.join("ca.crt")).unwrap()
    );
    let auth = format!("Authorization: Bearer {PLACEHOLDER}");
    let fixture_ca = fixture.join("ca.crt");
    let out = w
        .curl(&[
            "--cacert",
            fixture_ca.to_str().unwrap(),
            "-H",
            &auth,
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "https://localhost:443/node-ca",
        ])
        .await;
    assert_eq!(
        out, "200",
        "the client did not trust the leaf made from the earlier CA"
    );
    assert_eq!(
        w.received()[0].headers["authorization"],
        format!("Bearer {SECRET}")
    );
}

#[test]
fn refuses_to_replace_a_ca_it_cannot_read() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("ca.crt"), "not a certificate").unwrap();
    std::fs::write(dir.path().join("ca.key"), "not a key").unwrap();
    assert!(Ca::load_or_create(dir.path(), "t").is_err());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("ca.crt")).unwrap(),
        "not a certificate"
    );

    let half = tempfile::tempdir().unwrap();
    std::fs::write(half.path().join("ca.crt"), "x").unwrap();
    assert!(
        Ca::load_or_create(half.path(), "t").is_err(),
        "a certificate without its key"
    );
    assert!(!half.path().join("ca.key").exists());
}

#[test]
fn makes_a_ca_once_and_reads_the_same_one_after() {
    let dir = tempfile::tempdir().unwrap();
    let a = Ca::load_or_create(dir.path(), "t").unwrap();
    let b = Ca::load_or_create(dir.path(), "t").unwrap();
    assert_eq!(a.cert_pem, b.cert_pem);
    assert!(a.subject.contains("briq gateway (t)"), "{}", a.subject);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join("ca.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

/// A briq the gateway does not know yet: its name resolves only after `failures` lookups.
async fn new_briq(failures: usize, wait: Duration) -> (Arc<Config>, Arc<ApiState>) {
    credential_gateway::log::set_level("off");
    let config = json!({ "secrets": [], "briqs": [{ "id": "bq_new", "host": "new.internal", "secrets": [] }] });
    let (url, state) = fake_api(config).await;
    let lookups = Arc::new(AtomicUsize::new(0));
    let resolve: Resolve = Arc::new(move |_| {
        let n = lookups.fetch_add(1, Ordering::SeqCst) + 1;
        Box::pin(async move {
            if n <= failures {
                Err(std::io::Error::other("ENOTFOUND"))
            } else {
                Ok(vec!["fdaa::7".parse().unwrap()])
            }
        })
    });
    (
        Arc::new(Config::new(
            Arc::new(Api::new(&url, "gw-token")),
            resolve,
            wait,
        )),
        state,
    )
}

#[tokio::test]
async fn waits_for_a_new_briqs_name_one_refresh_a_second_for_every_connection() {
    let (config, api) = new_briq(2, Duration::from_secs(5)).await;
    let ip: IpAddr = "fdaa::7".parse().unwrap();
    let t0 = Instant::now();
    let (a, b) = tokio::join!(config.resolve_briq(ip), config.resolve_briq(ip));
    assert_eq!(
        (a.as_deref(), b.as_deref()),
        (Some("bq_new"), Some("bq_new"))
    );
    assert_eq!(api.configs.load(Ordering::SeqCst), 3);
    assert!(
        t0.elapsed() >= Duration::from_millis(1_900),
        "refreshes spaced by a second"
    );
}

#[tokio::test]
async fn gives_up_on_an_unknown_address_after_its_wait() {
    let (config, api) = new_briq(usize::MAX, Duration::from_millis(1_500)).await;
    let ip: IpAddr = "fdaa::7".parse().unwrap();
    assert_eq!(config.resolve_briq(ip).await, None);
    assert!(api.configs.load(Ordering::SeqCst) <= 3);
}

#[tokio::test]
async fn reads_a_response_whose_codings_come_in_two_headers() {
    let w = world().await;
    let auth = format!("Authorization: Bearer {PLACEHOLDER}");
    // `identity` then `gzip`: read as gzip, scrubbed.
    let out = w
        .curl(&[
            "--cacert",
            w.cacert(),
            "--compressed",
            "-H",
            &auth,
            "https://localhost:443/dup-encoding",
        ])
        .await;
    assert!(
        out.contains(&format!("\"auth\":\"Bearer {PLACEHOLDER}\"")),
        "{out}"
    );
    assert!(!out.contains(SECRET), "the real value reached the client");
}

#[tokio::test]
async fn refuses_a_response_it_cannot_read() {
    let w = world().await;
    let auth = format!("Authorization: Bearer {PLACEHOLDER}");
    let out = w
        .curl(&[
            "--cacert",
            w.cacert(),
            "-H",
            &auth,
            "-H",
            "x-test-encoding: gzip, br",
            "-w",
            "\n%{http_code}",
            "https://localhost:443/x",
        ])
        .await;
    assert!(out.ends_with("502"), "{out}");
    assert!(!out.contains(SECRET), "the real value reached the client");
}

/// A request on a connection kept open from before a secret was revoked: the secret is not put
/// in any more.
#[tokio::test]
async fn reads_which_secrets_apply_for_each_request_on_a_kept_alive_connection() {
    use hyper::client::conn::http1 as client;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let w = world().await;
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", w.proxy))
        .await
        .unwrap();
    tcp.write_all(b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n")
        .await
        .unwrap();
    let mut answer = Vec::new();
    while !answer.ends_with(b"\r\n\r\n") {
        answer.push(tcp.read_u8().await.unwrap());
    }
    assert!(
        answer.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&answer)
    );
    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read_to_string(&w.ca_pem).unwrap();
    let der = pem::parse(pem).unwrap().into_contents();
    roots
        .add(rustls_pki_types::CertificateDer::from(der))
        .unwrap();
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    let stream = tokio_rustls::TlsConnector::from(Arc::new(tls))
        .connect(name, tcp)
        .await
        .unwrap();
    let (mut send, conn) = client::handshake::<_, Body>(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = || {
        Request::builder()
            .uri("/kept")
            .header("host", "localhost")
            .header("authorization", format!("Bearer {PLACEHOLDER}"))
            .body(full(""))
            .unwrap()
    };
    send.send_request(req())
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    // TOKEN revoked: the briq no longer names it.
    w.api.config.lock().unwrap()["briqs"][0]["secrets"] = json!(["BODY"]);
    w.config.refresh().await.unwrap();
    send.send_request(req())
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    let got = w.received();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].headers["authorization"], format!("Bearer {SECRET}"));
    assert_eq!(
        got[1].headers["authorization"],
        format!("Bearer {PLACEHOLDER}")
    );
}

#[tokio::test]
async fn gives_no_secrets_to_an_address_two_briqs_claim() {
    credential_gateway::log::set_level("off");
    let config = json!({ "secrets": [], "briqs": [
        { "id": "bq_old", "host": "old.internal", "secrets": ["TOKEN"] },
        { "id": "bq_new", "host": "new.internal", "secrets": [] },
        { "id": "bq_other", "host": "other.internal", "secrets": [] },
    ]});
    let (url, _) = fake_api(config).await;
    let resolve: Resolve = Arc::new(|host| {
        Box::pin(async move {
            Ok(vec![
                if host == "other.internal" {
                    "10.0.0.9"
                } else {
                    "10.0.0.5"
                }
                .parse()
                .unwrap(),
            ])
        })
    });
    let config = Config::new(
        Arc::new(Api::new(&url, "gw-token")),
        resolve,
        Duration::from_millis(10),
    );
    config.refresh().await.unwrap();
    assert_eq!(config.briq_of("10.0.0.5".parse().unwrap()), None);
    assert_eq!(
        config.briq_of("10.0.0.9".parse().unwrap()).as_deref(),
        Some("bq_other")
    );
}

#[tokio::test]
async fn never_drops_an_event_that_put_a_secret_in() {
    let w = world().await;
    for i in 0..1_500 {
        w.events.record(
            Some("bq_test"),
            "localhost",
            &format!("JUNK{i}"),
            200,
            vec![],
        );
    }
    for i in 0..1_200 {
        w.events.record(
            Some("bq_test"),
            &format!("h{i}.example.com"),
            "GET",
            200,
            vec![],
        );
    }
    w.events.record(
        Some("bq_test"),
        "localhost",
        "get",
        200,
        vec!["TOKEN".into()],
    );
    w.events.flush().await;
    let posted = w.api.events.lock().unwrap().clone();
    let token: Vec<_> = posted
        .iter()
        .filter(|e| e["secrets"] == json!(["TOKEN"]))
        .collect();
    assert_eq!(token.len(), 1);
    assert_eq!(token[0]["method"], "GET");
    assert!(
        posted.iter().any(|e| e["method"] == "OTHER"),
        "a made-up method is OTHER"
    );
    assert!(posted.len() <= 1_002, "{}", posted.len());
}

#[tokio::test]
async fn body_limits_choose_buffering_or_streaming_without_losing_secrets() {
    for (held, max, chunked) in [(0, 1024, true), (1, 1024, false), (1, 8, true)] {
        let w = world_limits(None, held, max).await;
        let out = w
            .curl(&[
                "--cacert",
                w.cacert(),
                "--data-binary",
                BODY_PLACEHOLDER,
                "https://localhost:443/post",
            ])
            .await;
        let got = w.received();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].body, BODY_SECRET.as_bytes());
        assert_eq!(got[0].headers.contains_key("transfer-encoding"), chunked);
        assert_eq!(got[0].headers.contains_key("content-length"), !chunked);
        assert!(!out.contains(BODY_SECRET));
        assert!(out.contains(BODY_PLACEHOLDER));
    }
}
