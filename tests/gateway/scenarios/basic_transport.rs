fn basic_fixture_response(
    parts: &http::request::Parts,
    auth: Option<&str>,
    go: Arc<Notify>,
) -> Response<Body> {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    if parts.uri.path() == "/basic-bearer-challenge" {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(
                "www-authenticate",
                "Bearer realm=\"https://ungranted.invalid/token\",service=\"fixture\"",
            )
            .body(full("challenge only"))
            .unwrap();
    }
    let token = auth.unwrap().strip_prefix("Basic ").unwrap();
    let pair = STANDARD.decode(token).unwrap();
    let variants: Vec<_> = [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD]
        .into_iter()
        .map(|engine| engine.encode(&pair))
        .collect();
    let password = &pair[pair.iter().position(|byte| *byte == b':').unwrap() + 1..];
    let payload = json!({"auth": variants, "raw": String::from_utf8_lossy(password)}).to_string();
    let mut response = Response::builder()
        .header("content-type", "application/json")
        .header("authorization", auth.unwrap())
        .header("trailer", "x-final-credential");
    for (index, variant) in variants.iter().enumerate() {
        response = response.header(format!("x-basic-{index}"), variant);
    }
    let coding = parts
        .headers
        .get("x-fixture-coding")
        .map(|value| value.to_str().unwrap())
        .unwrap_or("identity");
    let bytes = match coding {
        "gzip" | "contradictory" | "broken" => {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(payload.as_bytes()).unwrap();
            response = response.header("content-encoding", "gzip");
            let mut bytes = encoder.finish().unwrap();
            if coding == "contradictory" {
                response = response.header("connection", "Content-Encoding");
            }
            if coding == "broken" {
                bytes.truncate(bytes.len() / 2);
            }
            bytes
        }
        "deflate" => {
            let mut encoder =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(payload.as_bytes()).unwrap();
            response = response.header("content-encoding", "deflate");
            encoder.finish().unwrap()
        }
        "br" => {
            response = response.header("content-encoding", "br");
            payload.into_bytes()
        }
        _ => payload.into_bytes(),
    };
    let mut frames: std::collections::VecDeque<Result<Frame<Bytes>, BoxError>> = bytes
        .into_iter()
        .map(|byte| Ok(Frame::data(Bytes::from(vec![byte]))))
        .collect();
    let mut trailers = HeaderMap::new();
    trailers.insert(
        "x-final-credential",
        HeaderValueForFixture::from_str(token).unwrap(),
    );
    frames.push_back(Ok(Frame::trailers(trailers)));
    let delay = parts.uri.path() == "/basic-delayed";
    let body = futures_util::stream::unfold((frames, delay), move |(mut frames, delay)| {
        let go = go.clone();
        async move {
            if delay {
                tokio::time::timeout(Duration::from_secs(5), go.notified())
                    .await
                    .unwrap();
            }
            frames.pop_front().map(|frame| (frame, (frames, false)))
        }
    });
    response.body(StreamBody::new(body).boxed_unsync()).unwrap()
}

use http::HeaderValue as HeaderValueForFixture;

struct BasicSession {
    send: hyper::client::conn::http1::SendRequest<Body>,
    connection: tokio::task::JoinHandle<Result<(), hyper::Error>>,
}
impl Drop for BasicSession {
    fn drop(&mut self) {
        self.connection.abort();
    }
}
async fn basic_session(w: &World) -> BasicSession {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", w.proxy))
            .await
            .unwrap();
        // Fragment the CONNECT and the TLS client's request writes independently of HTTP
        // body framing. Every operation has a fixture-wide bound, never a readiness sleep.
        for piece in b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n".chunks(7) {
            tcp.write_all(piece).await.unwrap();
        }
        let mut answer = Vec::new();
        while !answer.ends_with(b"\r\n\r\n") {
            assert!(answer.len() < 4096);
            answer.push(tcp.read_u8().await.unwrap());
        }
        assert!(answer.starts_with(b"HTTP/1.1 200"));
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls_pki_types::CertificateDer::from(
                pem::parse(std::fs::read(&w.ca_pem).unwrap())
                    .unwrap()
                    .into_contents(),
            ))
            .unwrap();
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let stream = tokio_rustls::TlsConnector::from(Arc::new(tls))
            .connect(
                rustls_pki_types::ServerName::try_from("localhost").unwrap(),
                tcp,
            )
            .await
            .unwrap();
        let (send, connection) =
            hyper::client::conn::http1::handshake::<_, Body>(TokioIo::new(stream))
                .await
                .unwrap();
        BasicSession {
            send,
            connection: tokio::spawn(connection),
        }
    })
    .await
    .expect("local TLS fixture exceeded bound")
}
fn basic_request(path: &str, auth: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header("host", "localhost")
        .header("authorization", auth)
        .body(full(""))
        .unwrap()
}
async fn basic_exchange(
    session: &mut BasicSession,
    request: Request<Body>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let response = session.send.send_request(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let mut body = response.into_body();
        let mut output = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.unwrap();
            assert!(
                frame.trailers_ref().is_none(),
                "gateway must drop response trailers"
            );
            if let Some(data) = frame.data_ref() {
                output.extend_from_slice(data);
            }
        }
        (status, headers, output)
    })
    .await
    .expect("local Basic exchange exceeded bound")
}

#[tokio::test]
async fn basic_transport_aliases_headers_streams_codings_and_trailers() {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    for username in ["a", "ab", "abc"] {
        let w = world().await;
        let generated_password = credentials::structured();
        let password = generated_password.as_str();
        assert_eq!(password.len() % 3, 0);
        w.api.config.lock().unwrap()["secrets"][0]["value"] = json!(password);
        w.config.refresh().await.unwrap();
        let real_pair = format!("{username}:{password}");
        let aliases: Vec<_> = [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD]
            .into_iter()
            .map(|engine| engine.encode(&real_pair))
            .collect();
        let mut session = basic_session(&w).await;
        for coding in ["identity", "gzip", "deflate"] {
            let auth = format!("Basic {}", basic_fixture(username, placeholder()));
            let mut request = basic_request("/basic-variants", &auth);
            request.headers_mut().insert(
                "x-fixture-coding",
                HeaderValueForFixture::from_static(coding),
            );
            let (status, headers, body) = basic_exchange(&mut session, request).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(headers["authorization"], auth);
            let output = format!("{headers:?}{}", String::from_utf8_lossy(&body));
            assert!(!output.contains(password));
            for alias in &aliases {
                assert!(!output.contains(alias), "encoded credential reached client");
            }
            assert!(String::from_utf8_lossy(&body).contains(placeholder()));
        }
        assert!(
            w.received()
                .iter()
                .all(|request| request.headers["authorization"]
                    == format!("Basic {}", STANDARD.encode(&real_pair)))
        );
    }
}

#[tokio::test]
async fn basic_transport_refuses_shapes_framing_duplicates_and_bad_values_before_forwarding() {
    let w = world().await;
    let mut session = basic_session(&w).await;
    let ordinary = basic_fixture("u", &credentials::ascii(6));
    let alternate = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE,
        format!("u:{}?", credentials::ascii(6)),
    );
    for auth in [
        "Basic".to_string(),
        format!("Basic {ordinary}="),
        format!("Basic {alternate}"),
        format!("Basic {ordinary}, Bearer {}", credentials::ascii(8)),
        format!(
            "Basic {}",
            basic_fixture(placeholder(), &credentials::ascii(6))
        ),
        format!(
            "Basic {}",
            basic_fixture(
                "u",
                &format!(
                    "prefix{token_placeholder}",
                    token_placeholder = placeholder()
                )
            )
        ),
        format!(
            "Basic {}",
            basic_fixture(
                "u",
                &format!(
                    "{token_placeholder}{body_marker}",
                    token_placeholder = placeholder(),
                    body_marker = body_placeholder()
                )
            )
        ),
        format!("Basic {}", credentials::ascii(8193)),
    ] {
        let (status, _, body) = basic_exchange(&mut session, basic_request("/echo", &auth)).await;
        assert!(
            status == StatusCode::BAD_REQUEST
                || status == StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );
        assert!(!String::from_utf8_lossy(&body).contains(placeholder()));
        assert!(w.received().is_empty());
    }
    for nominated in [false, true] {
        let mut request = basic_request(
            "/echo",
            &format!("Basic {}", basic_fixture("u", placeholder())),
        );
        if nominated {
            request.headers_mut().insert(
                "connection",
                HeaderValueForFixture::from_static("keep-alive, Authorization"),
            );
        } else {
            request.headers_mut().append(
                "authorization",
                HeaderValueForFixture::from_str(&format!(
                    "Basic {}",
                    basic_fixture("u", &credentials::ascii(16))
                ))
                .unwrap(),
            );
        }
        assert_eq!(
            basic_exchange(&mut session, request).await.0,
            StatusCode::BAD_REQUEST
        );
        assert!(w.received().is_empty());
    }
    for value in [
        String::new(),
        format!("{}\n", credentials::ascii(16)),
        format!("{}\u{007f}", credentials::ascii(16)),
        credentials::ascii(6144),
    ] {
        w.api.config.lock().unwrap()["secrets"][0]["value"] = json!(value);
        w.config.refresh().await.unwrap();
        let request = basic_request(
            "/echo",
            &format!("Basic {}", basic_fixture("u", placeholder())),
        );
        assert_eq!(
            basic_exchange(&mut session, request).await.0,
            StatusCode::BAD_REQUEST
        );
        assert!(w.received().is_empty());
    }
    w.events.flush().await;
    assert!(
        w.api.events.lock().unwrap().is_empty(),
        "no forwarded secret means no usage event"
    );
}

#[tokio::test]
async fn basic_transport_opaque_credentials_skip_generic_rewrite_and_keep_other_fields() {
    let w = world().await;
    w.api.config.lock().unwrap()["secrets"][0]["placeholder"] = json!("T");
    w.config.refresh().await.unwrap();
    let mut session = basic_session(&w).await;
    let ordinary = format!("bAsIc {}", basic_fixture("u", &credentials::ascii(16)));
    assert!(ordinary.contains('T')); // The public username fixes this encoded prefix.
    let mut request = basic_request("/echo", &ordinary);
    request
        .headers_mut()
        .insert("x-literal-control", HeaderValueForFixture::from_static("T"));
    let (status, _, _) = basic_exchange(&mut session, request).await;
    assert_eq!(status, StatusCode::OK);
    let got = w.received();
    assert_eq!(got[0].headers["authorization"], ordinary);
    assert_eq!(got[0].headers["x-literal-control"], token_secret());
}

#[tokio::test]
async fn basic_transport_denials_no_match_and_no_automatic_token_realm() {
    let w = world().await;
    let mut session = basic_session(&w).await;
    for deny in ["host", "grant", "header", "other"] {
        let mut config = team_config();
        match deny {
            "host" => config["secrets"][0]["hosts"] = json!(["ungranted.invalid"]),
            "grant" => config["briqs"][0]["secrets"] = json!(["BODY"]),
            "header" => config["secrets"][0]["locations"] = json!(["body"]),
            _ => {}
        }
        *w.api.config.lock().unwrap() = config;
        w.config.refresh().await.unwrap();
        let placeholder = if deny == "other" {
            other_placeholder()
        } else {
            placeholder()
        };
        let auth = format!("Basic {}", basic_fixture("u", placeholder));
        assert_eq!(
            basic_exchange(&mut session, basic_request("/echo", &auth))
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(w.received().last().unwrap().headers["authorization"], auth);
    }
    *w.api.config.lock().unwrap() = team_config();
    w.config.refresh().await.unwrap();
    let auth = format!("Basic {}", basic_fixture("u", placeholder()));
    let before = w.received().len();
    let (status, headers, _) = basic_exchange(
        &mut session,
        basic_request("/basic-bearer-challenge", &auth),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        headers["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("ungranted.invalid")
    );
    assert_eq!(
        w.received().len(),
        before + 1,
        "no automatic challenge fetch"
    );
}

#[tokio::test]
async fn basic_transport_inflight_rotation_and_next_request_revocation() {
    let w = world().await;
    let auth = format!("Basic {}", basic_fixture("u", placeholder()));
    let mut session = basic_session(&w).await;
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        session
            .send
            .send_request(basic_request("/basic-delayed", &auth)),
    )
    .await
    .unwrap()
    .unwrap();
    let rotated = credentials::ascii(14);
    w.api.config.lock().unwrap()["secrets"][0]["value"] = json!(rotated);
    w.config.refresh().await.unwrap();
    w.dest.go_on.notify_one();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(!String::from_utf8_lossy(&body).contains(token_secret()));
    assert!(!String::from_utf8_lossy(&body).contains(&basic_fixture("u", token_secret())));
    assert!(String::from_utf8_lossy(&body).contains(placeholder()));
    basic_exchange(&mut session, basic_request("/echo", &auth)).await;
    assert_eq!(
        w.received().last().unwrap().headers["authorization"],
        format!("Basic {}", basic_fixture("u", &rotated))
    );
    w.api.config.lock().unwrap()["briqs"][0]["secrets"] = json!(["BODY"]);
    w.config.refresh().await.unwrap();
    basic_exchange(&mut session, basic_request("/echo", &auth)).await;
    assert_eq!(w.received().last().unwrap().headers["authorization"], auth);
}

#[tokio::test]
async fn basic_transport_audit_deduplicates_basic_literal_body_and_flush_retry() {
    let w = world().await;
    w.api.config.lock().unwrap()["secrets"][0]["locations"] = json!(["header", "body"]);
    w.config.refresh().await.unwrap();
    w.api.events_down.store(true, Ordering::SeqCst);
    let mut session = basic_session(&w).await;
    let mut request = basic_request(
        "/echo",
        &format!("Basic {}", basic_fixture("audit-user", placeholder())),
    );
    request.headers_mut().insert(
        "x-literal-control",
        HeaderValueForFixture::from_static(placeholder()),
    );
    *request.body_mut() = full(placeholder());
    basic_exchange(&mut session, request).await;
    assert_eq!(w.received()[0].body, token_secret().as_bytes());
    w.events.flush().await;
    assert!(w.api.events.lock().unwrap().is_empty());
    w.api.events_down.store(false, Ordering::SeqCst);
    basic_audit_once(
        &w,
        "TOKEN",
        &basic_fixture("audit-user", token_secret()),
        "audit-user",
    )
    .await;
}

#[tokio::test]
async fn basic_transport_budget_refuses_before_forward_and_releases_response_owner() {
    let w = world_budget(300 * 1024).await;
    let auth = format!("Basic {}", basic_fixture("u", placeholder()));
    let mut first = basic_session(&w).await;
    let response = first
        .send
        .send_request(basic_request("/basic-delayed", &auth))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut second = basic_session(&w).await;
    let rejected = basic_exchange(&mut second, basic_request("/echo", &auth)).await;
    assert_eq!(rejected.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(w.received().len(), 1);
    w.dest.go_on.notify_one();
    response.into_body().collect().await.unwrap();
    assert_eq!(
        basic_exchange(&mut second, basic_request("/echo", &auth))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(w.received().len(), 2);
    let small = world_budget(64 * 1024 - 1).await;
    let mut session = basic_session(&small).await;
    assert_eq!(
        basic_exchange(&mut session, basic_request("/echo", &auth))
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(small.received().is_empty());
}

#[tokio::test]
async fn basic_transport_mixed_case_duplicate_definitions_and_expanded_header_cap() {
    let w = world().await;
    let mut session = basic_session(&w).await;
    let auth = format!("bAsIc {}", basic_fixture("public-user", placeholder()));
    assert_eq!(
        basic_exchange(&mut session, basic_request("/echo", &auth))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        w.received()[0].headers["authorization"],
        format!("Basic {}", basic_fixture("public-user", token_secret()))
    );
    let mut config = team_config();
    let mut duplicate = config["secrets"][0].clone();
    duplicate["name"] = json!("DUPLICATE");
    config["secrets"].as_array_mut().unwrap().push(duplicate);
    config["briqs"][0]["secrets"]
        .as_array_mut()
        .unwrap()
        .push(json!("DUPLICATE"));
    *w.api.config.lock().unwrap() = config;
    w.config.refresh().await.unwrap();
    assert_eq!(
        basic_exchange(&mut session, basic_request("/echo", &auth))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(w.received().len(), 1);
    let mut config = team_config();
    config["secrets"][0]["value"] = json!(credentials::ascii(5900));
    *w.api.config.lock().unwrap() = config;
    w.config.refresh().await.unwrap();
    let mut request = basic_request("/echo", &auth);
    request.headers_mut().insert(
        "x-header-padding",
        HeaderValueForFixture::from_str(&"p".repeat(60_000)).unwrap(),
    );
    assert_eq!(
        basic_exchange(&mut session, request).await.0,
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
    );
    assert_eq!(
        w.received().len(),
        1,
        "expanded block must be checked before forwarding"
    );
}

#[tokio::test]
async fn basic_transport_unsupported_and_broken_codings_never_expose_aliases() {
    let w = world().await;
    let auth = format!("Basic {}", basic_fixture("u", placeholder()));
    let mut session = basic_session(&w).await;
    for coding in ["br", "contradictory"] {
        let mut request = basic_request("/basic-variants", &auth);
        request.headers_mut().insert(
            "x-fixture-coding",
            HeaderValueForFixture::from_static(coding),
        );
        let (status, _, body) = basic_exchange(&mut session, request).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(!String::from_utf8_lossy(&body).contains(token_secret()));
        assert!(!String::from_utf8_lossy(&body).contains(&basic_fixture("u", token_secret())));
    }
    let mut request = basic_request("/basic-variants", &auth);
    request.headers_mut().insert(
        "x-fixture-coding",
        HeaderValueForFixture::from_static("broken"),
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        let response = session.send.send_request(request).await.unwrap();
        let mut body = response.into_body();
        let mut received = Vec::new();
        let mut failed = false;
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(frame) => {
                    if let Some(data) = frame.data_ref() {
                        received.extend_from_slice(data);
                    }
                }
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }
        assert!(
            failed,
            "truncated gzip must not be reported as a successful complete response"
        );
        assert!(!String::from_utf8_lossy(&received).contains(token_secret()));
        assert!(!String::from_utf8_lossy(&received).contains(&basic_fixture("u", token_secret())));
    })
    .await
    .expect("broken fixture exceeded bound");
}

#[tokio::test]
async fn basic_transport_exact_alias_wins_an_identical_literal_value_rule() {
    let w = world().await;
    let emitted = basic_fixture("public", token_secret());
    w.api.config.lock().unwrap()["secrets"][1]["value"] = json!(emitted);
    w.config.refresh().await.unwrap();
    let mut session = basic_session(&w).await;
    let original = format!("Basic {}", basic_fixture("public", placeholder()));
    let (_, headers, body) = basic_exchange(&mut session, basic_request("/echo", &original)).await;
    assert_eq!(headers["x-echo-auth"], original);
    assert!(String::from_utf8_lossy(&body).contains(&original));
    assert!(!String::from_utf8_lossy(&body).contains(&emitted));
}
