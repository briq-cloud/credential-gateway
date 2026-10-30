async fn admission_head(tcp: &mut tokio::net::TcpStream) -> Vec<u8> {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(tcp.read_u8().await.unwrap());
        }
        head
    })
    .await
    .unwrap()
}

async fn admission_connect(w: &World, authority: &str) -> (tokio::net::TcpStream, Vec<u8>) {
    use tokio::io::AsyncWriteExt;
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", w.proxy))
        .await
        .unwrap();
    tcp.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let head = admission_head(&mut tcp).await;
    (tcp, head)
}

async fn admission_health(w: &World) {
    use tokio::io::AsyncWriteExt;
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", w.proxy))
        .await
        .unwrap();
    tcp.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    assert!(admission_head(&mut tcp).await.starts_with(b"HTTP/1.1 200"));
}

async fn admission_wait_for_release(w: &World) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let (tcp, head) = admission_connect(w, "localhost:443").await;
            drop(tcp);
            if head.starts_with(b"HTTP/1.1 200") {
                break;
            }
            assert!(head.starts_with(b"HTTP/1.1 503"));
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

async fn admission_hold_outer(w: &World) -> tokio::net::TcpStream {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", w.proxy))
        .await
        .unwrap();
    tcp.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    assert!(admission_head(&mut tcp).await.starts_with(b"HTTP/1.1 200"));
    let mut body = [0; 3];
    tcp.read_exact(&mut body).await.unwrap();
    assert_eq!(&body, b"ok\n");
    // A partial next request must still consume the connection's original permit.
    tcp.write_all(b"GET /healthz HTTP/1.1\r\nHost:")
        .await
        .unwrap();
    tcp
}

#[tokio::test]
async fn admission_counts_outer_headers_and_keeps_local_health_available() {
    let w = world_admission(None, 2, 1024, Duration::from_secs(10), 1, "127.0.0.1").await;
    let held = admission_hold_outer(&w).await;
    admission_health(&w).await;
    let (_, head) = admission_connect(&w, "localhost:443").await;
    assert!(
        head.starts_with(b"HTTP/1.1 503"),
        "health reserve must not admit CONNECT"
    );
    use tokio::io::AsyncWriteExt;
    let mut plain = tokio::net::TcpStream::connect(("127.0.0.1", w.proxy))
        .await
        .unwrap();
    plain
        .write_all(b"GET http://localhost/healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    assert!(
        admission_head(&mut plain)
            .await
            .starts_with(b"HTTP/1.1 503")
    );
    drop(plain);
    drop(held);
    admission_wait_for_release(&w).await;
}

#[tokio::test]
async fn admission_reserve_is_bounded_and_partial_health_requests_expire() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let w = world_admission(None, 2, 1024, Duration::from_secs(10), 1, "127.0.0.1").await;
    let _held = admission_hold_outer(&w).await;
    let mut reserves = Vec::new();
    for _ in 0..2 {
        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", w.proxy))
            .await
            .unwrap();
        tcp.write_all(b"GET /healthz HTTP/1.1\r\nHost:")
            .await
            .unwrap();
        reserves.push(tcp);
        tokio::task::yield_now().await;
    }
    let mut excess = tokio::net::TcpStream::connect(("127.0.0.1", w.proxy))
        .await
        .unwrap();
    let mut byte = [0];
    let closed = tokio::time::timeout(Duration::from_secs(1), excess.read(&mut byte))
        .await
        .unwrap();
    assert!(
        matches!(closed, Ok(0) | Err(_)),
        "reserve must not grow beyond two sockets"
    );
    for mut tcp in reserves {
        let mut bytes = Vec::new();
        let _closed = tokio::time::timeout(Duration::from_secs(3), tcp.read_to_end(&mut bytes))
            .await
            .unwrap();
    }
    admission_health(&w).await;
}

#[tokio::test]
async fn admission_holds_permit_through_intercepted_tls_stream() {
    let w = world_admission(None, 2, 1024, Duration::from_secs(10), 1, "127.0.0.1").await;
    let proxy = format!("http://127.0.0.1:{}", w.proxy);
    let auth = format!("Authorization: Bearer {PLACEHOLDER}");
    let mut child = Command::new("curl")
        .args([
            "-sS",
            "-N",
            "--max-time",
            "5",
            "-x",
            &proxy,
            "--cacert",
            w.cacert(),
            "-H",
            &auth,
            "https://localhost:443/stream",
        ])
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(2), lines.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(line, "data: one\n");
    let (_, head) = admission_connect(&w, "localhost:443").await;
    assert!(
        head.starts_with(b"HTTP/1.1 503"),
        "upgrade must retain admission permit"
    );
    admission_health(&w).await;
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    drop(lines);
    admission_wait_for_release(&w).await;
}

#[tokio::test]
async fn admission_holds_permit_through_raw_tunnel() {
    let w = world_admission(None, 2, 1024, Duration::from_secs(10), 1, "127.0.0.1").await;
    let (tunnel, head) = admission_connect(&w, &format!("localhost:{}", w.dest.port)).await;
    assert!(head.starts_with(b"HTTP/1.1 200"));
    let (_, head) = admission_connect(&w, "localhost:443").await;
    assert!(
        head.starts_with(b"HTTP/1.1 503"),
        "raw tunnel must retain admission permit"
    );
    admission_health(&w).await;
    drop(tunnel);
    admission_wait_for_release(&w).await;
}

#[tokio::test]
async fn admission_health_reserve_accepts_ipv4_mapped_loopback() {
    // Like main.rs: an IPv4 loopback client reaches the IPv6 listener as ::ffff:127.0.0.1.
    let w = world_admission(None, 2, 1024, Duration::from_secs(10), 1, "::").await;
    let _held = admission_hold_outer(&w).await;
    admission_health(&w).await;
    let (_, head) = admission_connect(&w, "localhost:443").await;
    assert!(head.starts_with(b"HTTP/1.1 503"));
}

#[tokio::test]
async fn amplified_request_headers_are_rejected_before_sending_secrets() {
    let w = world().await;
    w.api.config.lock().unwrap()["secrets"][0]["value"] = json!("x".repeat(4096));
    w.config.refresh().await.unwrap();
    let header = format!("Authorization: {}", PLACEHOLDER.repeat(32));
    let out = w
        .curl(&[
            "--max-time",
            "5",
            "--cacert",
            w.cacert(),
            "-H",
            &header,
            "-w",
            "%{http_code}",
            "https://localhost:443/echo",
        ])
        .await;
    assert!(out.ends_with("431"), "{out}");
    assert!(w.received().is_empty());
}

#[tokio::test]
async fn amplified_response_headers_fail_closed() {
    let w = world().await;
    w.api.config.lock().unwrap()["secrets"][0]["value"] = json!("A");
    w.config.refresh().await.unwrap();
    let auth = format!("Authorization: {PLACEHOLDER}");
    let out = w
        .curl(&[
            "--max-time",
            "5",
            "--cacert",
            w.cacert(),
            "-H",
            &auth,
            "-w",
            "%{http_code}",
            "https://localhost:443/amplified-header",
        ])
        .await;
    assert!(out.ends_with("502"), "{out}");
}

#[tokio::test]
async fn rewritten_headers_share_one_aggregate_budget() {
    let w = world().await;
    w.api.config.lock().unwrap()["secrets"][0]["value"] = json!("x".repeat(4096));
    w.config.refresh().await.unwrap();
    let one = format!("X-One: {}", PLACEHOLDER.repeat(10));
    let two = format!("X-Two: {}", PLACEHOLDER.repeat(10));
    let out = w
        .curl(&[
            "--max-time",
            "5",
            "--cacert",
            w.cacert(),
            "-H",
            &one,
            "-H",
            &two,
            "-w",
            "%{http_code}",
            "https://localhost:443/echo",
        ])
        .await;
    assert!(out.ends_with("431"), "{out}");
    assert!(w.received().is_empty());
}

/// A CONNECT session reuses its upstream socket, but does not leave it idle after disconnect.
#[tokio::test]
async fn upstream_keepalive_is_scoped_to_the_connect_session() {
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
    let driver = tokio::spawn(conn);
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
    send.send_request(req())
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    assert_eq!(
        w.dest.sockets.accepted.load(Ordering::SeqCst),
        1,
        "successive requests should reuse one upstream TLS connection"
    );
    assert_eq!(w.dest.sockets.active.load(Ordering::SeqCst), 1);
    drop(send);
    driver.abort();
    let _ = driver.await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while w.dest.sockets.active.load(Ordering::SeqCst) != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("idle upstream socket outlived its incoming CONNECT session");
}

#[tokio::test]
async fn oversized_api_responses_preserve_the_last_good_config() {
    for chunked in [false, true] {
        let (url, state) = fake_api(team_config()).await;
        state.config_chunked.store(chunked, Ordering::SeqCst);
        let api = Arc::new(Api::new(&url, "gw-token").with_response_limit(2048));
        let config = Config::new(api, local(), Duration::from_secs(1));
        config.refresh().await.unwrap();
        state.config.lock().unwrap()["secrets"][0]["value"] = json!("x".repeat(4096));
        assert!(config.refresh().await.is_err());
        let secrets = config.for_host("localhost", Some("bq_test"));
        assert_eq!(
            secrets.iter().find(|s| s.name == "TOKEN").unwrap().value,
            SECRET
        );
    }
}

fn many_credentials(count: usize, value_bytes: usize) -> Value {
    let secrets: Vec<_> = (0..count)
        .map(|i| {
            json!({
                "name": format!("KEY_{i}"), "placeholder": format!("briq_secret_{i:016x}"),
                "value": format!("{i:08}") + &"x".repeat(value_bytes - 8),
                "hosts": ["localhost"], "locations": ["header"]
            })
        })
        .collect();
    let names: Vec<_> = (0..count).map(|i| format!("KEY_{i}")).collect();
    json!({"secrets":secrets,"briqs":[{"id":"bq_test","host":"localhost","secrets":names}]})
}

async fn budget_status(w: &World) -> String {
    w.curl(&[
        "--max-time",
        "3",
        "--cacert",
        w.cacert(),
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "-H",
        "Authorization: briq_secret_0000000000000000",
        "https://localhost:443/echo",
    ])
    .await
}

#[tokio::test]
async fn a_large_valid_config_is_refused_before_upstream_then_rotation_can_fit() {
    let w = world_budget(1024 * 1024).await;
    *w.api.config.lock().unwrap() = many_credentials(50, 4096);
    w.config.refresh().await.unwrap();
    assert_eq!(budget_status(&w).await, "503");
    assert!(
        w.received().is_empty(),
        "refusal must precede any upstream disclosure"
    );
    assert_eq!(w.dest.sockets.accepted.load(Ordering::SeqCst), 0);
    assert!(w.config.has_for_host("localhost", Some("bq_test")));
    let borrowed = w
        .config
        .for_host_with("localhost", Some("bq_test"), |secrets| {
            assert_eq!(secrets.count(), 50);
            Err::<(), _>("no owned selection")
        });
    assert!(matches!(borrowed, Err("no owned selection")));
    // The next request estimates the new generation, rather than retaining a stale decision.
    *w.api.config.lock().unwrap() = many_credentials(1, 64);
    w.config.refresh().await.unwrap();
    assert_eq!(budget_status(&w).await, "200");
    assert_eq!(
        w.received()[0].headers["authorization"],
        format!("00000000{}", "x".repeat(56))
    );
}

#[tokio::test]
async fn weighted_stream_admission_keeps_health_and_recovers_after_cancellation() {
    // One 10×1KiB selection fits in2MiB; two do not. A tiny selection fits alongside it.
    let w = world_budget(2 * 1024 * 1024).await;
    *w.api.config.lock().unwrap() = many_credentials(10, 1024);
    w.config.refresh().await.unwrap();
    let proxy = format!("http://127.0.0.1:{}", w.proxy);
    let mut child = Command::new("curl")
        .args([
            "-sS",
            "-N",
            "--max-time",
            "4",
            "-x",
            &proxy,
            "--cacert",
            w.cacert(),
            "https://localhost:443/stream",
        ])
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    tokio::time::timeout(
        Duration::from_secs(2),
        BufReader::new(child.stdout.as_mut().unwrap()).read_line(&mut line),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(line, "data: one\n");
    assert_eq!(budget_status(&w).await, "503");
    assert_eq!(w.received().len(), 1);
    let health = w
        .curl(&[
            "--max-time",
            "2",
            &format!("http://localhost:{}/healthz", w.proxy),
        ])
        .await;
    assert!(health.contains("ok"), "{health}");
    *w.api.config.lock().unwrap() = many_credentials(1, 64);
    w.config.refresh().await.unwrap();
    assert_eq!(
        budget_status(&w).await,
        "200",
        "admission is weighted, not just a request count"
    );
    *w.api.config.lock().unwrap() = many_credentials(10, 1024);
    w.config.refresh().await.unwrap();
    assert_eq!(
        budget_status(&w).await,
        "503",
        "the old stream retains its original reservation"
    );
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if budget_status(&w).await == "200" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}
