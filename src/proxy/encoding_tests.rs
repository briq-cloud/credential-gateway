use super::*;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

struct UnreadBody {
    polls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

impl http_body::Body for UnreadBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
}

impl Drop for UnreadBody {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn refuses_large_window_codings_without_reading_the_body() {
    for encoding in ["br", "zstd", "gzip, br", "unknown"] {
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let body = UnreadBody {
            polls: polls.clone(),
            drops: drops.clone(),
        };
        assert!(decoded(body, encoding).await.is_none());
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn connection_nominations_and_duplicates_cannot_hide_a_coded_secret_echo() {
    for duplicate in [false, true] {
        let mut headers = HeaderMap::new();
        headers.append(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        if duplicate {
            headers.append(
                header::CONTENT_ENCODING,
                HeaderValue::from_static("identity"),
            );
            headers.append(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        }
        headers.append(
            header::CONNECTION,
            HeaderValue::from_static("Content-Encoding"),
        );
        assert!(!forward_headers(&headers).contains_key(header::CONTENT_ENCODING));
        assert!(response_encoding(&headers).is_err());
        let refusal = encoding_refusal();
        assert_eq!(refusal.status(), StatusCode::BAD_GATEWAY);
        let body = refusal.into_body().collect().await.unwrap().to_bytes();
        assert!(!String::from_utf8_lossy(&body).contains("real-secret-value"));
        assert!(body.starts_with(b"credential gateway: response encoding"));
    }
}

fn compress(data: &[u8], encoding: &str) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
    match encoding {
        "gzip" | "x-gzip" => {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(data).unwrap();
            encoder.finish().unwrap()
        }
        "deflate" => {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(data).unwrap();
            encoder.finish().unwrap()
        }
        "raw-deflate" => {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(data).unwrap();
            encoder.finish().unwrap()
        }
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn supported_codings_still_scrub_plaintext_including_duplicate_identity_metadata() {
    let value = "real-secret-value";
    let placeholder = "secret-placeholder";
    for coding in ["gzip", "x-gzip", "deflate", "raw-deflate"] {
        let wire_coding = if coding == "raw-deflate" {
            "deflate"
        } else {
            coding
        };
        let mut headers = HeaderMap::new();
        headers.append(
            header::CONTENT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        headers.append(
            header::CONTENT_ENCODING,
            HeaderValue::from_str(wire_coding).unwrap(),
        );
        let selected = response_encoding(&headers).unwrap().unwrap();
        let body = Full::new(Bytes::from(compress(value.as_bytes(), coding)));
        let body = decoded(body, &selected).await.unwrap();
        let replacer = Arc::new(Replacer::new(&[(value, placeholder)]).unwrap().unwrap());
        let output = Rewrite::new(body, Stream::new(replacer))
            .collect()
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(output.as_ref(), placeholder.as_bytes());
    }
    let mut headers = HeaderMap::new();
    headers.append(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    headers.append(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    assert!(response_encoding(&headers).is_err());
}
