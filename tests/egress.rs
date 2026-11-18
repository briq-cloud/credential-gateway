//! A gateway born with a hostname policy, against a fake API and fake destinations. The client is
//! raw: it picks the CONNECT target, the TLS server name and every request byte itself. DNS and
//! the transport are fakes behind the dialer's seams; address classification is the real one, so
//! a destination is "public" here only by being a public-looking literal that the transport maps
//! to a local fake server.
#![allow(dead_code, unused_imports)]

include!("gateway/shared.rs");

use std::collections::HashMap;
use std::net::SocketAddr;

use credential_gateway::dialer::{Connect, Dialer};
use credential_gateway::egress::{Egress, EgressPolicy};
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const API_IP: &str = "93.184.216.34";
const SECOND_IP: &str = "93.184.216.35";

#[derive(Default)]
struct Dns {
    answers: Mutex<HashMap<String, Vec<IpAddr>>>,
    lookups: Mutex<Vec<String>>,
}

impl Dns {
    fn set(&self, name: &str, ips: &[&str]) {
        let ips = ips.iter().map(|ip| ip.parse().unwrap()).collect();
        self.answers.lock().unwrap().insert(name.into(), ips);
    }
    fn lookups(&self) -> Vec<String> {
        self.lookups.lock().unwrap().clone()
    }
}

struct Dest {
    port: u16,
    received: Arc<Mutex<Vec<Received>>>,
    sockets: Arc<SocketCounts>,
}

fn dest_ca(dir: &Path) -> CertificateDer<'static> {
    Ca::load_or_create(&dir.join("dest-ca"), "destination")
        .unwrap()
        .cert_der()
}

async fn dest(dir: &Path, name: &str) -> Dest {
    let leafs =
        Leafs::new(Ca::load_or_create(&dir.join("dest-ca"), "destination").unwrap()).unwrap();
    let tls = TlsAcceptor::from(leafs.for_host(name).unwrap());
    let received = Arc::new(Mutex::new(Vec::new()));
    let rec = received.clone();
    let sockets = Arc::new(SocketCounts::default());
    let port = serve_observed(Some(tls), sockets.clone(), move |req: Request<Incoming>| {
        let rec = rec.clone();
        async move {
            let (parts, body) = req.into_parts();
            let body = body.collect().await.unwrap().to_bytes().to_vec();
            rec.lock().unwrap().push(Received {
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                headers: parts.headers.clone(),
                body,
            });
            let header = |n: &str| {
                parts
                    .headers
                    .get(n)
                    .map(|v| v.to_str().unwrap().to_string())
            };
            match parts.uri.path() {
                "/redirect" => Response::builder()
                    .status(302)
                    .header("location", "https://other.example.net/steal")
                    .body(full(""))
                    .unwrap(),
                "/close" => Response::builder()
                    .header("connection", "close")
                    .body(full("closed"))
                    .unwrap(),
                _ => Response::new(full(
                    json!({ "auth": header("authorization"), "host": header("host") }).to_string(),
                )),
            }
        }
    })
    .await;
    Dest {
        port,
        received,
        sockets,
    }
}

struct Edge {
    _dir: tempfile::TempDir,
    proxy: u16,
    api: Arc<ApiState>,
    dns: Arc<Dns>,
    dialed: Arc<Mutex<Vec<SocketAddr>>>,
    api_dest: Dest,
    second_dest: Dest,
    gateway_ca: CertificateDer<'static>,
    events: Arc<Events>,
    policy: Arc<EgressPolicy>,
}

fn secrets_for_api_host() -> Value {
    json!({
        "secrets": [{ "name": "TOKEN", "placeholder": PLACEHOLDER, "value": SECRET,
                      "hosts": ["api.example.com"], "locations": ["header"] }],
        "briqs": [{ "id": "bq_test", "host": "localhost", "secrets": ["TOKEN"], "own": [] }],
    })
}

fn policy_for(hosts: &[&str]) -> Arc<EgressPolicy> {
    Arc::new(
        EgressPolicy::parse(
            &json!({ "policy_format": 1, "namespace": "ns", "team_id": "tm_1", "briq_id": "bq_test", "hosts": hosts })
                .to_string(),
        )
        .unwrap(),
    )
}

/// A restricted gateway. `config` is the API's answer; `config_down` makes the API fail from the
/// start, so the gateway never loads a config.
async fn edge(hosts: &[&str], config: Value, config_down: bool) -> Edge {
    credential_gateway::log::set_level("off");
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let ca_der = dest_ca(dir.path());
    let api_dest = dest(dir.path(), "api.example.com").await;
    let second_dest = dest(dir.path(), "second.example.com").await;
    let (url, api_state) = fake_api(config).await;
    let ca = Ca::load_or_create(&dir.path().join("ca"), "test team").unwrap();
    let gateway_ca = ca.cert_der();
    let api = Arc::new(Api::new(&url, "gw-token"));
    api.register_ca(&ca.cert_pem).await.unwrap();
    api_state.config_down.store(config_down, Ordering::SeqCst);
    let cfg = Arc::new(Config::new(api.clone(), local(), Duration::from_secs(1)));
    let _ = cfg.refresh().await;
    let events = Events::new(api);

    let dns = Arc::new(Dns::default());
    dns.set("api.example.com", &[API_IP]);
    dns.set("second.example.com", &[SECOND_IP]);
    let lookups = dns.clone();
    let resolve: Resolve = Arc::new(move |name| {
        let dns = lookups.clone();
        Box::pin(async move {
            dns.lookups.lock().unwrap().push(name.clone());
            let answer = dns.answers.lock().unwrap().get(&name).cloned();
            answer.ok_or_else(|| std::io::Error::other("nxdomain"))
        })
    });
    let routes: HashMap<IpAddr, u16> = HashMap::from([
        (API_IP.parse().unwrap(), api_dest.port),
        (SECOND_IP.parse().unwrap(), second_dest.port),
    ]);
    let dialed = Arc::new(Mutex::new(Vec::new()));
    let record = dialed.clone();
    let connect: Connect = Arc::new(move |addr| {
        record.lock().unwrap().push(addr);
        let port = routes.get(&addr.ip()).copied();
        Box::pin(async move {
            match port {
                Some(port) => TcpStream::connect(("127.0.0.1", port)).await,
                None => Err(std::io::Error::other("no route")),
            }
        })
    });
    let policy = policy_for(hosts);
    let gw = Gateway::with_egress(
        cfg,
        Arc::new(Leafs::new(ca).unwrap()),
        events.clone(),
        Options {
            upstream_ca: vec![ca_der],
            ..Options::default()
        },
        Some(Egress {
            policy: policy.clone(),
            dialer: Dialer::new(resolve, connect),
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap().port();
    tokio::spawn(gw.serve(listener));
    Edge {
        _dir: dir,
        proxy,
        api: api_state,
        dns,
        dialed,
        api_dest,
        second_dest,
        gateway_ca,
        events,
        policy,
    }
}

fn get(host: &str, extra: &str) -> String {
    format!("GET /x HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n{extra}\r\n")
}

fn code(response: &str) -> u16 {
    response
        .strip_prefix("HTTP/1.1 ")
        .or_else(|| response.strip_prefix("HTTP/1.0 "))
        .and_then(|r| r.get(..3))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

impl Edge {
    async fn connect(&self, authority: &str) -> Result<TcpStream, u16> {
        let mut tcp = TcpStream::connect(("127.0.0.1", self.proxy)).await.unwrap();
        tcp.write_all(
            format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            match tokio::time::timeout(Duration::from_secs(10), tcp.read(&mut byte)).await {
                Ok(Ok(1)) => head.push(byte[0]),
                _ => break,
            }
        }
        let status = code(&String::from_utf8_lossy(&head));
        if status == 200 { Ok(tcp) } else { Err(status) }
    }

    async fn tls(
        &self,
        tcp: TcpStream,
        sni: &str,
    ) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.gateway_ca.clone()).unwrap();
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect(ServerName::try_from(sni.to_string()).unwrap(), tcp)
            .await
    }

    /// CONNECT to `authority`, TLS with `sni`, send `raw`, read to the end. The error is the
    /// CONNECT status, or 0 when the TLS handshake failed.
    async fn exchange(&self, authority: &str, sni: &str, raw: &str) -> Result<String, u16> {
        let tcp = self.connect(authority).await?;
        let mut tls = self.tls(tcp, sni).await.map_err(|_| 0u16)?;
        tls.write_all(raw.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut out)).await;
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    async fn ok(&self, host: &str, raw: &str) -> String {
        self.exchange(&format!("{host}:443"), host, raw)
            .await
            .unwrap()
    }

    fn at_api_dest(&self) -> Vec<Received> {
        self.api_dest.received.lock().unwrap().clone()
    }
    fn dialed(&self) -> Vec<SocketAddr> {
        self.dialed.lock().unwrap().clone()
    }
}

#[tokio::test]
async fn an_allowed_connect_is_intercepted_even_with_no_secret() {
    let edge = edge(
        &["api.example.com"],
        json!({ "secrets": [], "briqs": [] }),
        false,
    )
    .await;
    let res = edge
        .ok("api.example.com", &get("api.example.com", ""))
        .await;
    assert_eq!(code(&res), 200, "{res}");
    assert!(res.contains(r#""host":"api.example.com""#), "{res}");
    let seen = edge.at_api_dest();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].headers["host"], "api.example.com");
    // Only a gateway-signed certificate got the client this far: it was terminated, not tunnelled.
    assert_eq!(
        edge.dialed(),
        vec![format!("{API_IP}:443").parse::<SocketAddr>().unwrap()]
    );
    assert_eq!(edge.dns.lookups(), ["api.example.com"]);
}

#[tokio::test]
async fn secret_substitution_and_audit_are_unchanged_on_an_allowed_host() {
    let edge = edge(&["api.example.com"], secrets_for_api_host(), false).await;
    let extra = format!("Authorization: Bearer {PLACEHOLDER}\r\n");
    let res = edge
        .ok("api.example.com", &get("api.example.com", &extra))
        .await;
    assert_eq!(code(&res), 200, "{res}");
    assert!(!res.contains(SECRET) && res.contains(PLACEHOLDER), "{res}");
    assert_eq!(
        edge.at_api_dest()[0].headers["authorization"],
        format!("Bearer {SECRET}")
    );
    edge.events.flush().await;
    let events = edge.api.events.lock().unwrap().clone();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["secrets"], json!(["TOKEN"]));
}

#[tokio::test]
async fn everything_off_policy_is_refused_before_any_lookup() {
    let edge = edge(&["api.example.com"], secrets_for_api_host(), false).await;
    for target in [
        "other.example.net:443",
        "api.example.com:8443",
        "api.example.com:80",
        "api.example.com",
        "x.api.example.com:443",
        "example.com:443",
        "93.184.216.34:443",
        "127.0.0.1:443",
        "[::1]:443",
        "[2606:4700:4700::1111]:443",
        "localhost:443",
        "api.example.com.:443",
        "*.example.com:443",
        "user@api.example.com:443",
    ] {
        assert!(
            matches!(edge.connect(target).await, Err(400 | 403)),
            "{target}"
        );
    }
    assert!(edge.dns.lookups().is_empty(), "{:?}", edge.dns.lookups());
    assert!(edge.dialed().is_empty());
    for plain in [
        "GET http://api.example.com/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
        "POST http://other.example.net/ HTTP/1.1\r\nHost: other.example.net\r\nContent-Length: 0\r\n\r\n",
    ] {
        let mut tcp = TcpStream::connect(("127.0.0.1", edge.proxy)).await.unwrap();
        tcp.write_all(plain.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut out)).await;
        assert_eq!(code(&String::from_utf8_lossy(&out)), 403);
    }
    let mut health = TcpStream::connect(("127.0.0.1", edge.proxy)).await.unwrap();
    health
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    let _ = health.read_to_end(&mut out).await;
    assert_eq!(code(&String::from_utf8_lossy(&out)), 200);
    // The control: the same gateway still serves the allowed host.
    assert_eq!(
        code(
            &edge
                .ok("api.example.com", &get("api.example.com", ""))
                .await
        ),
        200
    );
}

#[tokio::test]
async fn an_empty_policy_denies_every_host() {
    let edge = edge(&[], secrets_for_api_host(), false).await;
    for target in ["api.example.com:443", "second.example.com:443"] {
        assert_eq!(edge.connect(target).await.err(), Some(403));
    }
    assert!(edge.dns.lookups().is_empty() && edge.dialed().is_empty());
}

#[tokio::test]
async fn unknown_and_secretless_consumers_are_bound_by_the_same_policy() {
    // No briq in the config: the caller's address is unknown, so it never gets secrets.
    let edge = edge(
        &["api.example.com"],
        json!({ "secrets": [], "briqs": [] }),
        false,
    )
    .await;
    assert_eq!(
        edge.connect("second.example.com:443").await.err(),
        Some(403)
    );
    assert_eq!(edge.connect("other.example.net:443").await.err(), Some(403));
    let extra = format!("Authorization: Bearer {PLACEHOLDER}\r\n");
    let res = edge
        .ok("api.example.com", &get("api.example.com", &extra))
        .await;
    assert_eq!(code(&res), 200, "{res}");
    assert_eq!(
        edge.at_api_dest()[0].headers["authorization"],
        format!("Bearer {PLACEHOLDER}")
    );
}

#[tokio::test]
async fn host_sni_and_method_mismatches_never_reach_the_destination() {
    let edge = edge(
        &["api.example.com", "second.example.com"],
        secrets_for_api_host(),
        false,
    )
    .await;
    let extra = format!("Authorization: Bearer {PLACEHOLDER}\r\n");
    // TLS server name other than the CONNECT host: no handshake.
    for sni in [
        "second.example.com",
        "other.example.net",
        "API.example.com.x",
    ] {
        assert_eq!(
            edge.exchange("api.example.com:443", sni, &get("api.example.com", &extra))
                .await
                .err(),
            Some(0),
            "{sni}"
        );
    }
    let bad: [(&str, u16); 12] = [
        (
            "GET /x HTTP/1.1\r\nHost: second.example.com\r\nConnection: close\r\n",
            400,
        ),
        (
            "GET /x HTTP/1.1\r\nHost: api.example.com:8443\r\nConnection: close\r\n",
            400,
        ),
        (
            "GET /x HTTP/1.1\r\nHost: api.example.com:80\r\nConnection: close\r\n",
            400,
        ),
        (
            "GET /x HTTP/1.1\r\nHost: 93.184.216.34\r\nConnection: close\r\n",
            400,
        ),
        (
            "GET /x HTTP/1.1\r\nHost: api.example.com\r\nHost: api.example.com\r\nConnection: close\r\n",
            400,
        ),
        (
            "GET /x HTTP/1.1\r\nHost: api.example.com\r\nHost: second.example.com\r\nConnection: close\r\n",
            400,
        ),
        ("GET /x HTTP/1.1\r\nConnection: close\r\n", 400),
        (
            "GET https://api.example.com/x HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n",
            400,
        ),
        (
            "CONNECT second.example.com:443 HTTP/1.1\r\nHost: second.example.com:443\r\nConnection: close\r\n",
            403,
        ),
        (
            "GET /x HTTP/1.1\r\nHost: api.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n",
            403,
        ),
        (
            "GET /x HTTP/1.1\r\nHost: api.example.com\r\nConnection: keep-alive, Upgrade\r\n",
            403,
        ),
        ("GET /x HTTP/1.0\r\nHost: api.example.com\r\n", 403),
    ];
    for (head, want) in bad {
        let res = edge
            .exchange(
                "api.example.com:443",
                "api.example.com",
                &format!("{head}{extra}\r\n"),
            )
            .await
            .unwrap();
        assert_eq!(code(&res), want, "{head}: {res}");
    }
    assert!(
        edge.at_api_dest().is_empty(),
        "{:?}",
        edge.at_api_dest().len()
    );
    assert!(edge.second_dest.received.lock().unwrap().is_empty());
    // The control, with the default port written out, and a differently cased name.
    let res = edge
        .ok("api.example.com", &get("API.Example.com:443", &extra))
        .await;
    assert_eq!(code(&res), 200, "{res}");
    assert_eq!(
        edge.at_api_dest()[0].headers["authorization"],
        format!("Bearer {SECRET}")
    );
}

#[tokio::test]
async fn a_redirect_is_returned_and_the_next_host_is_decided_afresh() {
    let edge = edge(
        &["api.example.com", "second.example.com"],
        secrets_for_api_host(),
        false,
    )
    .await;
    let res = edge
        .ok(
            "api.example.com",
            "GET /redirect HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n",
        )
        .await;
    assert_eq!(code(&res), 302, "{res}");
    assert!(
        res.contains("location: https://other.example.net/steal"),
        "{res}"
    );
    assert_eq!(
        edge.at_api_dest().len(),
        1,
        "the gateway does not follow it"
    );
    assert_eq!(edge.connect("other.example.net:443").await.err(), Some(403));
    assert!(
        !edge
            .dns
            .lookups()
            .contains(&"other.example.net".to_string())
    );
}

#[tokio::test]
async fn two_names_on_one_address_do_not_let_a_session_address_the_other() {
    // Two allowed names answered by the same address: the session still serves only its own.
    let edge = edge(
        &["api.example.com", "second.example.com"],
        secrets_for_api_host(),
        false,
    )
    .await;
    edge.dns.set("second.example.com", &[API_IP]);
    let tcp = edge.connect("second.example.com:443").await.unwrap();
    let mut tls = edge.tls(tcp, "second.example.com").await.unwrap();
    tls.write_all(
        get(
            "api.example.com",
            &format!("Authorization: Bearer {PLACEHOLDER}\r\n"),
        )
        .replace("Connection: close\r\n", "")
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut out = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut out))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(code(&String::from_utf8_lossy(&out[..n])), 400);
    assert!(edge.at_api_dest().is_empty());
}

#[tokio::test]
async fn rebinding_after_validation_is_not_followed() {
    let edge = edge(
        &["api.example.com"],
        json!({ "secrets": [], "briqs": [] }),
        false,
    )
    .await;
    let tcp = edge.connect("api.example.com:443").await.unwrap();
    // The name now answers with a private address: the session must not look again.
    edge.dns.set(
        "api.example.com",
        &["127.0.0.1", "10.0.0.7", "169.254.169.254"],
    );
    let mut tls = edge.tls(tcp, "api.example.com").await.unwrap();
    for _ in 0..3 {
        // The destination closes after each answer, so the pool opens a new socket each time.
        tls.write_all(b"GET /close HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
            .await
            .unwrap();
        let mut seen = Vec::new();
        while !String::from_utf8_lossy(&seen).contains("closed") {
            let mut buf = [0u8; 1024];
            let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert!(n > 0, "{}", String::from_utf8_lossy(&seen));
            seen.extend_from_slice(&buf[..n]);
        }
        assert_eq!(code(&String::from_utf8_lossy(&seen)), 200);
    }
    assert_eq!(edge.dns.lookups(), ["api.example.com"]);
    let dialed = edge.dialed();
    assert!(dialed.len() >= 3);
    assert!(
        dialed
            .iter()
            .all(|a| a == &format!("{API_IP}:443").parse::<SocketAddr>().unwrap())
    );
    assert_eq!(
        edge.api_dest.sockets.accepted.load(Ordering::SeqCst),
        dialed.len()
    );
    // A new CONNECT is a new decision: it sees the private answer and is refused.
    assert_eq!(edge.connect("api.example.com:443").await.err(), Some(403));
}

#[tokio::test]
async fn any_non_public_or_missing_answer_refuses_the_connect() {
    let edge = edge(
        &["api.example.com"],
        json!({ "secrets": [], "briqs": [] }),
        false,
    )
    .await;
    for (ips, want) in [
        (vec!["127.0.0.1"], 403),
        (vec![API_IP, "10.1.2.3"], 403),
        (vec!["::ffff:93.184.216.34"], 403),
        (vec!["fd00::1"], 403),
        (vec!["100.64.0.1"], 403),
        (vec!["192.0.2.1"], 403),
        (vec![], 502),
    ] {
        edge.dns.set("api.example.com", &ips);
        assert_eq!(
            edge.connect("api.example.com:443").await.err(),
            Some(want),
            "{ips:?}"
        );
    }
    assert!(edge.dialed().is_empty());
    edge.dns.answers.lock().unwrap().remove("api.example.com");
    assert_eq!(edge.connect("api.example.com:443").await.err(), Some(502));
    edge.dns.set("api.example.com", &[API_IP]);
    assert!(edge.connect("api.example.com:443").await.is_ok());
}

#[tokio::test]
async fn a_secret_refresh_outage_does_not_drop_the_birth_policy() {
    let edge = edge(&["api.example.com"], secrets_for_api_host(), false).await;
    edge.api.config_down.store(true, Ordering::SeqCst);
    assert_eq!(
        code(
            &edge
                .ok("api.example.com", &get("api.example.com", ""))
                .await
        ),
        200
    );
    assert_eq!(
        edge.connect("second.example.com:443").await.err(),
        Some(403)
    );
    // A gateway that never managed to read a config enforces the policy too.
    let blind = edge_blind().await;
    assert_eq!(
        code(
            &blind
                .ok("api.example.com", &get("api.example.com", ""))
                .await
        ),
        200
    );
    assert_eq!(
        blind.connect("second.example.com:443").await.err(),
        Some(403)
    );
    assert_eq!(
        blind.connect("other.example.net:443").await.err(),
        Some(403)
    );
}

async fn edge_blind() -> Edge {
    edge(&["api.example.com"], secrets_for_api_host(), true).await
}

#[tokio::test]
async fn the_policy_object_is_immutable_and_reports_its_own_binding() {
    let edge = edge(&["second.example.com", "api.example.com"], json!({}), false).await;
    assert_eq!(
        edge.policy.hosts(),
        ["api.example.com", "second.example.com"]
    );
    let b = edge.policy.binding();
    assert_eq!((b.policy_format, b.enforcement_version), (1, 1));
    assert!(b.policy_digest.starts_with("sha256:") && b.policy_digest.len() == 71);
}

fn gateway_binary(policy: Option<&str>, api_url: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_credential-gateway"));
    cmd.env_clear()
        .env("BRIQ_API_URL", api_url)
        .env("BRIQ_GATEWAY_TOKEN", "gw-token")
        .env("GATEWAY_PORT", "0")
        .env("GATEWAY_STATE_DIR", tempfile::tempdir().unwrap().keep());
    if let Some(policy) = policy {
        cmd.env("BRIQ_EGRESS_POLICY", policy);
    }
    cmd
}

#[tokio::test]
async fn a_malformed_policy_stops_the_binary_before_it_registers_or_listens() {
    let (url, api) = fake_api(json!({})).await;
    for bad in [
        "",
        "{",
        "null",
        r#"{"policy_format":1,"namespace":"n","team_id":"t","briq_id":"b","hosts":["*.a.com"]}"#,
    ] {
        let out = gateway_binary(Some(bad), &url).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{bad}");
        assert!(
            api.ca.lock().unwrap().is_empty(),
            "the CA was registered before the policy was read"
        );
        assert!(!String::from_utf8_lossy(&out.stderr).contains("a.com"));
    }
}

#[tokio::test]
async fn the_status_helper_refuses_bad_arguments_and_a_gateway_without_a_policy() {
    let challenge = "ab".repeat(32);
    let helper = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_credential-gateway"))
            .args(args)
            .env("BRIQ_EGRESS_POLICY", "ignored")
            .env("GATEWAY_STATE_DIR", "/nonexistent")
            .output()
            .unwrap()
    };
    for args in [
        vec!["policy-status"],
        vec!["policy-status", "short"],
        vec!["policy-status", &challenge.to_uppercase()],
        vec!["policy-status", &challenge, "extra"],
    ] {
        let out = helper(&args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(out.stdout.is_empty());
        assert_eq!(
            String::from_utf8_lossy(&out.stderr),
            "policy-status: unavailable\n"
        );
    }
    // Well-formed, and no gateway is enforcing a policy on this machine's fixed socket: failure.
    if !std::path::Path::new("/run/credential-gateway/policy.sock").exists() {
        let out = helper(&["policy-status", &challenge]);
        assert_eq!(out.status.code(), Some(1));
        assert!(out.stdout.is_empty());
    }
}
