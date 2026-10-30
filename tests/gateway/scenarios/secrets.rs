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
