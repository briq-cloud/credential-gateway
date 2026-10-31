// Supported Basic password transport and deliberately unsupported encoded payloads.

fn basic_fixture(user: &str, password: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
}

async fn no_auth_material_in_audit(w: &World, wire: &str) {
    w.events.flush().await;
    let events = w.api.events.lock().unwrap().clone();
    assert!(events.iter().all(|event| event["secrets"] == json!([])));
    let serialized = serde_json::to_string(&events).unwrap();
    for material in [SECRET, BODY_SECRET, PLACEHOLDER, BODY_PLACEHOLDER, wire] {
        assert!(
            !serialized.contains(material),
            "audit must carry names and request metadata only"
        );
    }
}

#[tokio::test]
async fn auth_contract_git_basic_password_is_injected_and_encoded_echo_is_scrubbed() {
    let w = world().await;
    let credentials = format!("fixture-user:{PLACEHOLDER}");
    let expected = format!("Basic {}", basic_fixture("fixture-user", PLACEHOLDER));
    let output = w
        .curl(&[
            "--noproxy",
            "",
            "--cacert",
            w.cacert(),
            "--basic",
            "--user",
            &credentials,
            "-D",
            "-",
            "https://localhost:443/echo",
        ])
        .await;
    let received = w.received();
    assert_eq!(received.len(), 1);
    assert_eq!(
        received[0].headers["authorization"],
        format!("Basic {}", basic_fixture("fixture-user", SECRET))
    );
    assert!(output.contains(&expected));
    assert!(!output.contains(SECRET));
    basic_audit_once(&w, "TOKEN", &expected, "fixture-user").await;
}

#[tokio::test]
async fn auth_contract_actual_git_challenge_uses_the_authorized_password() {
    let w = world().await;
    let home = w._dir.path().join("git-home");
    std::fs::create_dir(&home).unwrap();
    let proxy = format!("http://127.0.0.1:{}", w.proxy);
    let url = format!("https://fixture-user:{PLACEHOLDER}@localhost:443/git/repository.git");
    let mut command = Command::new("git");
    // No inherited helper, user/system configuration, proxy bypass, tracing or credential
    // agent. This disposable client can address only the fixed local HTTPS fixture.
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", &home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ALLOW_PROTOCOL", "https")
        .current_dir(&home)
        .args(["-c", "credential.helper=", "-c", "http.version=HTTP/1.1"])
        .args(["-c", &format!("http.proxy={proxy}")])
        .args(["-c", &format!("http.sslCAInfo={}", w.cacert())])
        .args(["ls-remote", &url])
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(8), command.output())
        .await
        .expect("local Git exchange exceeded its bound")
        .unwrap();
    assert!(
        output.status.success(),
        "local Git protocol fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let received = w.received();
    assert_eq!(
        received.len(),
        2,
        "one challenge, then one authenticated request"
    );
    assert!(!received[0].headers.contains_key("authorization"));
    let expected = format!("Basic {}", basic_fixture("fixture-user", PLACEHOLDER));
    assert_eq!(
        received[1].headers["authorization"],
        format!("Basic {}", basic_fixture("fixture-user", SECRET))
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
    basic_audit_once(&w, "TOKEN", &expected, "fixture-user").await;
}

#[tokio::test]
async fn auth_contract_docker_config_auth_exercises_only_direct_basic_transport() {
    use base64::Engine as _;
    let w = world().await;
    // This parses the auth-file representation and sends its Basic wire form. It does not
    // claim to exercise a Docker daemon, registry challenge/token exchange or image pull.
    let encoded = basic_fixture("registry-user", PLACEHOLDER);
    let config_path = w._dir.path().join("config.json");
    std::fs::write(
        &config_path,
        json!({"auths": {"localhost:443": {"auth": encoded}}}).to_string(),
    )
    .unwrap();
    let config: Value = serde_json::from_slice(&std::fs::read(config_path).unwrap()).unwrap();
    let auth = config["auths"]["localhost:443"]["auth"].as_str().unwrap();
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(auth)
            .unwrap(),
        format!("registry-user:{PLACEHOLDER}").as_bytes()
    );
    let header = format!("Authorization: Basic {auth}");
    let output = w
        .curl(&[
            "--noproxy",
            "",
            "--cacert",
            w.cacert(),
            "-H",
            &header,
            "https://localhost:443/v2/",
        ])
        .await;
    assert_eq!(
        w.received()[0].headers["authorization"],
        format!("Basic {}", basic_fixture("registry-user", SECRET))
    );
    assert!(output.contains(auth));
    assert!(!output.contains(SECRET));
    basic_audit_once(&w, "TOKEN", auth, "registry-user").await;
}

#[tokio::test]
async fn auth_contract_encoded_body_stays_encoded_when_body_substitution_streams() {
    let w = world_limits(None, 0, 1).await;
    let encoded = basic_fixture("registry-user", BODY_PLACEHOLDER);
    let payload =
        json!({"auths": {"localhost:443": {"auth": encoded}}, "literal": BODY_PLACEHOLDER})
            .to_string();
    let output = w
        .curl(&[
            "--noproxy",
            "",
            "--cacert",
            w.cacert(),
            "-X",
            "POST",
            "-H",
            "Transfer-Encoding: chunked",
            "--data-binary",
            &payload,
            "https://localhost:443/echo",
        ])
        .await;
    let received = w.received();
    let body: Value = serde_json::from_slice(&received[0].body).unwrap();
    assert_eq!(body["auths"]["localhost:443"]["auth"], encoded);
    assert_eq!(
        body["literal"], BODY_SECRET,
        "positive control: literal body rewriting ran"
    );
    assert!(!received[0].headers.contains_key("content-length"));
    assert!(output.contains(&encoded));
    assert!(output.contains(BODY_PLACEHOLDER));
    assert!(!output.contains(BODY_SECRET));
    w.events.flush().await;
    let audit = w.api.events.lock().unwrap().clone();
    assert!(
        audit
            .iter()
            .any(|event| event["secrets"] == json!(["BODY"]))
    );
    let audit = serde_json::to_string(&audit).unwrap();
    assert!(!audit.contains(BODY_SECRET) && !audit.contains(&encoded));
}

#[test]
fn auth_contract_every_stream_split_preserves_encoded_and_rewrites_literal_bytes() {
    use credential_gateway::rewrite::{Replacer, Stream};
    let encoded = basic_fixture("u", PLACEHOLDER);
    let input = format!("auth={encoded}; literal={PLACEHOLDER}");
    let expected = format!("auth={encoded}; literal={SECRET}");
    let replace = Arc::new(Replacer::new(&[(PLACEHOLDER, SECRET)]).unwrap().unwrap());
    for at in 0..=input.len() {
        let mut stream = Stream::new(replace.clone());
        let mut output = stream.push(&input.as_bytes()[..at]);
        output.extend(stream.push(&input.as_bytes()[at..]));
        output.extend(stream.finish());
        assert_eq!(output, expected.as_bytes(), "fragment boundary {at}");
    }
}

#[tokio::test]
async fn auth_contract_host_and_identity_selection_still_fence_literal_substitution() {
    for deny_host in [true, false] {
        let w = world().await;
        if deny_host {
            w.api.config.lock().unwrap()["secrets"][0]["hosts"] = json!(["different.invalid"]);
        } else {
            w.api.config.lock().unwrap()["briqs"][0]["secrets"] = json!(["BODY"]);
        }
        w.config.refresh().await.unwrap();
        let auth = format!("Authorization: Bearer {PLACEHOLDER}");
        let output = w
            .curl(&[
                "--noproxy",
                "",
                "--cacert",
                w.cacert(),
                "-H",
                &auth,
                "https://localhost:443/echo",
            ])
            .await;
        assert_eq!(
            w.received()[0].headers["authorization"],
            format!("Bearer {PLACEHOLDER}")
        );
        assert!(output.contains(PLACEHOLDER));
        assert!(!output.contains(SECRET));
        no_auth_material_in_audit(&w, &auth).await;
    }
}

async fn basic_audit_once(w: &World, name: &str, wire: &str, user: &str) {
    w.events.flush().await;
    let events = w.api.events.lock().unwrap().clone();
    let uses: Vec<_> = events
        .iter()
        .filter(|event| event["secrets"] == json!([name]))
        .collect();
    assert_eq!(uses.len(), 1);
    assert_eq!(uses[0]["count"], 1);
    let serialized = serde_json::to_string(&events).unwrap();
    for material in [SECRET, BODY_SECRET, PLACEHOLDER, wire, user] {
        assert!(
            !serialized.contains(material),
            "no credential bytes in audit"
        );
    }
}
