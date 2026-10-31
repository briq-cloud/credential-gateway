#[tokio::test]
async fn refuses_connection_nominated_coding_on_a_real_compressed_secret_echo() {
    for (path, mode) in [("echo", "single"), ("dup-encoding", "duplicate")] {
        let w = world().await;
        let auth = format!(
            "Authorization: Bearer {token_placeholder}",
            token_placeholder = placeholder()
        );
        let nomination = format!("x-test-connection-encoding: {mode}");
        let out = w
            .curl(&[
                "--cacert",
                w.cacert(),
                "-H",
                &auth,
                "-H",
                "x-test-gzip: 1",
                "-H",
                &nomination,
                "-w",
                "\n%{http_code}",
                &format!("https://localhost:443/{path}"),
            ])
            .await;
        assert!(out.ends_with("502"), "{out}");
        assert!(out.contains("response encoding cannot be read"), "{out}");
        assert!(
            !out.contains(token_secret()),
            "the real value reached the client"
        );
        assert_eq!(
            w.received()[0].headers["authorization"],
            format!("Bearer {token}", token = token_secret())
        );
    }
}

#[tokio::test]
async fn refuses_brotli_and_zstandard_before_returning_a_secret_bearing_body() {
    for coding in ["br", "zstd"] {
        let w = world().await;
        let auth = format!(
            "Authorization: Bearer {token_placeholder}",
            token_placeholder = placeholder()
        );
        let encoding = format!("x-test-encoding: {coding}");
        let out = w
            .curl(&[
                "--cacert",
                w.cacert(),
                "-H",
                &auth,
                "-H",
                &encoding,
                "-w",
                "\n%{http_code}",
                "https://localhost:443/echo",
            ])
            .await;
        assert!(out.ends_with("502"), "{out}");
        assert!(
            !out.contains(token_secret()),
            "the real value reached the client"
        );
    }
}
