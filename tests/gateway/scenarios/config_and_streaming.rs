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

#[tokio::test]
async fn config_outage_and_malformed_config_preserve_last_good_then_recover() {
    let w = world().await;
    w.api.config_down.store(true, Ordering::SeqCst);
    assert!(w.config.refresh().await.is_err());
    let auth = format!("Authorization: Bearer {PLACEHOLDER}");
    // Last-known secrets remain usable during a control-plane outage.
    let out = w
        .curl(&[
            "--max-time",
            "5",
            "--cacert",
            w.cacert(),
            "-H",
            &auth,
            "https://localhost:443/echo",
        ])
        .await;
    assert!(out.contains(PLACEHOLDER));
    assert!(!out.contains(SECRET));
    w.api.config_down.store(false, Ordering::SeqCst);
    *w.api.config.lock().unwrap() = json!({"secrets": "broken"});
    assert!(w.config.refresh().await.is_err());
    let out = w
        .curl(&[
            "--max-time",
            "5",
            "--cacert",
            w.cacert(),
            "-H",
            &auth,
            "https://localhost:443/echo",
        ])
        .await;
    assert!(out.contains(PLACEHOLDER));
    assert!(!out.contains(SECRET));
    *w.api.config.lock().unwrap() = team_config();
    w.api.config.lock().unwrap()["briqs"][0]["secrets"] = json!([]);
    w.config.refresh().await.unwrap();
    w.curl(&[
        "--max-time",
        "5",
        "--cacert",
        w.cacert(),
        "-H",
        &auth,
        "https://localhost:443/echo",
    ])
    .await;
    let got = w.received();
    assert_eq!(got.len(), 3);
    assert_eq!(got[0].headers["authorization"], format!("Bearer {SECRET}"));
    assert_eq!(got[1].headers["authorization"], format!("Bearer {SECRET}"));
    assert_eq!(
        got[2].headers["authorization"],
        format!("Bearer {PLACEHOLDER}")
    );
}

#[tokio::test]
async fn connection_churn_and_aborted_tls_do_not_break_healthy_requests() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let w = world().await;
    for _ in 0..4 {
        let attempts = (0..64).map(|_| async {
            let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", w.proxy))
                .await
                .unwrap();
            tcp.write_all(b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n")
                .await
                .unwrap();
            let mut reply = Vec::new();
            while !reply.ends_with(b"\r\n\r\n") {
                reply.push(tcp.read_u8().await.unwrap());
            }
            assert!(reply.starts_with(b"HTTP/1.1 200"));
            // Disconnect halfway through a TLS record, before a handshake completes.
            tcp.write_all(&[22, 3, 3, 0, 100, 1]).await.unwrap();
        });
        tokio::time::timeout(
            Duration::from_secs(10),
            futures_util::future::join_all(attempts),
        )
        .await
        .unwrap();
        let auth = format!("Authorization: Bearer {PLACEHOLDER}");
        let out = w
            .curl(&[
                "--max-time",
                "5",
                "--cacert",
                w.cacert(),
                "-H",
                &auth,
                "https://localhost:443/echo",
            ])
            .await;
        assert!(out.contains(PLACEHOLDER), "{out}");
        assert!(!out.contains(SECRET));
    }
    assert_eq!(w.received().len(), 4);
}

#[tokio::test]
async fn concurrent_body_pressure_keeps_substitution_and_scrubbing_correct() {
    let w = world_limits(None, 2, 1024).await;
    let data = format!("{}{BODY_PLACEHOLDER}{}", "x".repeat(4096), "y".repeat(4096));
    let file = w._dir.path().join("stress.txt");
    std::fs::write(&file, &data).unwrap();
    let at = format!("@{}", file.display());
    let calls = (0..32).map(|_| async {
        let out = w
            .curl(&[
                "--max-time",
                "10",
                "--cacert",
                w.cacert(),
                "--data-binary",
                &at,
                "https://localhost:443/echo",
            ])
            .await;
        assert!(out.contains(BODY_PLACEHOLDER));
        assert!(!out.contains(BODY_SECRET));
    });
    tokio::time::timeout(
        Duration::from_secs(20),
        futures_util::future::join_all(calls),
    )
    .await
    .unwrap();
    let got = w.received();
    assert_eq!(got.len(), 32);
    for request in got {
        assert_eq!(
            request.body,
            data.replace(BODY_PLACEHOLDER, BODY_SECRET).as_bytes()
        );
    }
}

#[tokio::test]
async fn an_upstream_reset_does_not_expose_a_partial_secret_or_poison_later_requests() {
    let w = world().await;
    let proxy = format!("http://127.0.0.1:{}", w.proxy);
    let auth = format!("Authorization: Bearer {PLACEHOLDER}");
    use tokio::io::AsyncReadExt;
    let mut child = Command::new("curl")
        .args([
            "-sS",
            "-N",
            "--max-time",
            "5",
            "--fail",
            "-x",
            &proxy,
            "--cacert",
            w.cacert(),
            "-H",
            &auth,
            "https://localhost:443/broken-stream",
        ])
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut safe = [0u8; 7];
    tokio::time::timeout(Duration::from_secs(2), stdout.read_exact(&mut safe))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&safe, b"before ");
    w.dest.go_on.notify_one();
    let mut tail = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stdout.read_to_end(&mut tail))
        .await
        .unwrap()
        .unwrap();
    assert!(
        !child.wait().await.unwrap().success(),
        "truncated upstream must fail"
    );
    let body = String::from_utf8_lossy(&tail);
    assert!(!body.contains(SECRET));
    assert!(
        !body.contains(&SECRET[..10]),
        "a possible secret prefix must stay withheld: {body}"
    );
    let healthy = w
        .curl(&[
            "--max-time",
            "5",
            "--cacert",
            w.cacert(),
            "-H",
            &auth,
            "https://localhost:443/echo",
        ])
        .await;
    assert!(healthy.contains(PLACEHOLDER));
    assert!(!healthy.contains(SECRET));
}

#[tokio::test]
async fn stalled_upstream_streams_allow_other_requests_and_recover_after_client_cancellation() {
    let w = world().await;
    let auth = format!("Authorization: Bearer {PLACEHOLDER}");
    let proxy = format!("http://127.0.0.1:{}", w.proxy);
    let mut children = Vec::new();
    for _ in 0..16 {
        children.push(
            Command::new("curl")
                .args([
                    "-sS",
                    "-N",
                    "--max-time",
                    "3",
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
                .unwrap(),
        );
    }
    for child in &mut children {
        let mut lines = BufReader::new(child.stdout.as_mut().unwrap());
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(2), lines.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(line, "data: one\n");
    }
    assert_eq!(
        w.received().iter().filter(|r| r.uri == "/stream").count(),
        16
    );
    let healthy = w
        .curl(&[
            "--max-time",
            "5",
            "--cacert",
            w.cacert(),
            "-H",
            &auth,
            "https://localhost:443/echo",
        ])
        .await;
    assert!(healthy.contains(PLACEHOLDER));
    assert!(!healthy.contains(SECRET));
    for child in children {
        let out = child.wait_with_output().await.unwrap();
        assert!(!out.status.success());
        assert!(!String::from_utf8_lossy(&out.stdout).contains(SECRET));
    }
    let healthy = w
        .curl(&[
            "--max-time",
            "5",
            "--cacert",
            w.cacert(),
            "-H",
            &auth,
            "https://localhost:443/echo",
        ])
        .await;
    assert!(healthy.contains(PLACEHOLDER));
}

#[tokio::test]
async fn incomplete_tls_handshakes_expire_and_healthy_clients_still_work() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let w = world_options(None, 2, 1024, Duration::from_millis(100)).await;
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", w.proxy))
        .await
        .unwrap();
    tcp.write_all(b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n")
        .await
        .unwrap();
    let mut reply = Vec::new();
    while !reply.ends_with(b"\r\n\r\n") {
        reply.push(tcp.read_u8().await.unwrap());
    }
    assert!(reply.starts_with(b"HTTP/1.1 200"));
    tcp.write_all(&[22, 3, 3, 0, 100, 1]).await.unwrap();
    let mut rest = Vec::new();
    // Without the gateway deadline this waits forever: the peer never finishes TLS.
    tokio::time::timeout(Duration::from_secs(2), tcp.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    let auth = format!("Authorization: Bearer {PLACEHOLDER}");
    let out = w
        .curl(&[
            "--max-time",
            "5",
            "--cacert",
            w.cacert(),
            "-H",
            &auth,
            "https://localhost:443/echo",
        ])
        .await;
    assert!(out.contains(PLACEHOLDER));
    assert!(!out.contains(SECRET));
}

#[tokio::test]
async fn amplified_bodies_stream_when_rewritten_output_exceeds_buffer_budget() {
    let w = world_limits(None, 2, 1024).await;
    let long_value = "secret-expanded-".repeat(256);
    w.api.config.lock().unwrap()["secrets"][1]["value"] = json!(long_value);
    w.config.refresh().await.unwrap();
    // The input fits in 1KiB, but the rewritten output does not.
    let input = BODY_PLACEHOLDER.repeat(16);
    assert!(input.len() < 1024);
    let out = w
        .curl(&[
            "--max-time",
            "5",
            "--cacert",
            w.cacert(),
            "--data-binary",
            &input,
            "https://localhost:443/echo",
        ])
        .await;
    let got = w.received();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].body, long_value.repeat(16).as_bytes());
    assert!(
        !got[0].headers.contains_key("content-length"),
        "amplified output must not be buffered whole"
    );
    assert_eq!(got[0].headers["transfer-encoding"], "chunked");
    assert!(out.contains(BODY_PLACEHOLDER));
    assert!(!out.contains(&long_value));
}
