use super::*;
use crate::retained::Retained;
use crate::rewrite::{Replacer, Rewrite, Stream};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::net::TcpListener;
use tokio::sync::Notify;

#[derive(Default)]
struct Endpoint {
    down: AtomicBool,
    hold: AtomicBool,
    active: AtomicUsize,
    maximum: AtomicUsize,
    calls: AtomicUsize,
    received: Mutex<Vec<Value>>,
    started: Notify,
    release: Notify,
}
async fn setup(count: usize, bytes: usize) -> (Arc<Events>, Arc<Endpoint>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = Arc::new(Endpoint::default());
    let url = format!("http://{}", listener.local_addr().unwrap());
    let service = api.clone();
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let service = service.clone();
            tokio::spawn(async move {
                let handler = service_fn(move |request: Request<Incoming>| {
                    let service = service.clone();
                    async move {
                        let active = service.active.fetch_add(1, Ordering::SeqCst) + 1;
                        service.maximum.fetch_max(active, Ordering::SeqCst);
                        service.calls.fetch_add(1, Ordering::SeqCst);
                        let body = request.into_body().collect().await.unwrap().to_bytes();
                        assert!(body.len() <= BATCH_BYTES);
                        let json: Value = serde_json::from_slice(&body).unwrap();
                        assert!(json["events"].as_array().unwrap().len() <= BATCH);
                        let down = service.down.load(Ordering::SeqCst);
                        service.started.notify_one();
                        if service.hold.load(Ordering::SeqCst) {
                            service.release.notified().await;
                        }
                        if !down {
                            service
                                .received
                                .lock()
                                .unwrap()
                                .extend(json["events"].as_array().unwrap().iter().cloned());
                        }
                        service.active.fetch_sub(1, Ordering::SeqCst);
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(if down {
                                    StatusCode::SERVICE_UNAVAILABLE
                                } else {
                                    StatusCode::OK
                                })
                                .body(Full::new(Bytes::from_static(b"{}")))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(socket), handler)
                    .await;
            });
        }
    });
    (
        Events::with_limits(
            Arc::new(Api::new(&url, "offline-token")),
            count,
            bytes,
            10,
            32 * 1024,
        ),
        api,
    )
}
fn admitted(events: &Arc<Events>, host: &str, names: &[&str]) -> Arc<RequestAudit> {
    events
        .admit(Some("bq_test"), host, "GET", names.iter().copied())
        .unwrap()
        .unwrap()
}
fn finish(events: &Arc<Events>, host: &str, names: &[&str]) {
    let audit = admitted(events, host, names);
    audit.used(names.iter().map(|name| (*name).into()).collect());
    audit.arm();
    audit.finish(200);
}

#[tokio::test]
async fn outage_keeps_unique_hosts_and_secret_subsets_bounded_until_recovery() {
    let (events, api) = setup(2, 64 * 1024).await;
    api.down.store(true, Ordering::SeqCst);
    finish(&events, "a.example.com", &["A"]);
    finish(&events, "b.example.com", &["A", "B"]);
    let charged = events.secret.bytes.used();
    for _ in 0..3 {
        events.flush().await;
        assert_eq!(events.pending.lock().unwrap().len(), 2);
        assert_eq!(events.secret.slots.available_permits(), 0);
        assert_eq!(events.secret.bytes.used(), charged);
        assert!(
            events
                .admit(Some("bq_test"), "c.example.com", "GET", ["B"].into_iter())
                .is_err()
        );
    }
    assert!(api.received.lock().unwrap().is_empty());
    api.down.store(false, Ordering::SeqCst);
    events.flush().await;
    assert_eq!(api.received.lock().unwrap().len(), 2);
    assert_eq!(events.secret.slots.available_permits(), 2);
    assert_eq!(events.secret.bytes.used(), 0);
    finish(&events, "c.example.com", &["B"]);
}

#[tokio::test]
async fn same_key_merges_and_failed_batch_reinsert_preserve_exact_counts() {
    let (events, api) = setup(2, 64 * 1024).await;
    api.down.store(true, Ordering::SeqCst);
    finish(&events, "a.example.com", &["A"]);
    finish(&events, "a.example.com", &["A"]);
    assert_eq!(events.secret.slots.available_permits(), 1);
    events.flush().await;
    finish(&events, "a.example.com", &["A"]);
    api.down.store(false, Ordering::SeqCst);
    events.flush().await;
    let got = api.received.lock().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0]["count"], 3);
    assert_eq!(events.secret.bytes.used(), 0);
}

#[tokio::test]
async fn concurrent_flush_is_serial_and_cancellation_restores_unsent_entries() {
    let (events, api) = setup(2, 64 * 1024).await;
    finish(&events, "a.example.com", &["A"]);
    api.down.store(true, Ordering::SeqCst);
    api.hold.store(true, Ordering::SeqCst);
    let first = tokio::spawn({
        let events = events.clone();
        async move { events.flush().await }
    });
    tokio::time::timeout(Duration::from_secs(2), api.started.notified())
        .await
        .unwrap();
    let second = tokio::spawn({
        let events = events.clone();
        async move { events.flush().await }
    });
    tokio::task::yield_now().await;
    assert_eq!(api.calls.load(Ordering::SeqCst), 1);
    assert_eq!(events.secret.slots.available_permits(), 1);
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    // The aborted call can still reach the receiver: force it to fail before release, while
    // the requeued event is sent once by the serialized second flush.
    api.down.store(true, Ordering::SeqCst);
    api.hold.store(false, Ordering::SeqCst);
    api.release.notify_one();
    second.await.unwrap();
    assert_eq!(events.pending.lock().unwrap().len(), 1);
    assert_eq!(events.secret.slots.available_permits(), 1);
    api.down.store(false, Ordering::SeqCst);
    events.flush().await;
    assert_eq!(
        api.received
            .lock()
            .unwrap()
            .iter()
            .map(|event| event["count"].as_u64().unwrap())
            .sum::<u64>(),
        1
    );
    // A canceled HTTP request may briefly overlap server work; separate normal concurrency
    // below verifies only one non-canceled flush call is in flight.
}

#[tokio::test]
async fn concurrent_successful_flushes_send_one_batch_and_release_its_permits() {
    let (events, api) = setup(2, 64 * 1024).await;
    finish(&events, "a.example.com", &["A"]);
    api.hold.store(true, Ordering::SeqCst);
    let first = tokio::spawn({
        let events = events.clone();
        async move { events.flush().await }
    });
    tokio::time::timeout(Duration::from_secs(2), api.started.notified())
        .await
        .unwrap();
    finish(&events, "b.example.com", &["B"]);
    let second = tokio::spawn({
        let events = events.clone();
        async move { events.flush().await }
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(30), api.started.notified())
            .await
            .is_err()
    );
    assert_eq!(api.calls.load(Ordering::SeqCst), 1);
    api.hold.store(false, Ordering::SeqCst);
    api.release.notify_one();
    first.await.unwrap();
    second.await.unwrap();
    assert_eq!(api.maximum.load(Ordering::SeqCst), 1);
    assert_eq!(api.received.lock().unwrap().len(), 2);
    assert_eq!(events.secret.slots.available_permits(), 2);
}

#[tokio::test]
async fn cancellation_records_once_only_after_arming_and_last_upload_owner() {
    let (events, api) = setup(1, 32 * 1024).await;
    drop(admitted(&events, "a.example.com", &["A"]));
    assert!(events.pending.lock().unwrap().is_empty());
    let audit = admitted(&events, "a.example.com", &["A"]);
    let replacer = Arc::new(Replacer::new(&[("placeholder", "value")]).unwrap().unwrap());
    let stream = Stream::new(replacer);
    audit.body(stream.hits(), ["A"].into_iter());
    audit.arm();
    let mut upload = Retained::new(
        Rewrite::new(Full::new(Bytes::from_static(b"placeholder")), stream),
        audit.clone(),
    );
    let frame = upload.frame().await.unwrap().unwrap().into_data().unwrap();
    drop(upload);
    drop(audit);
    assert!(events.pending.lock().unwrap().is_empty());
    assert_eq!(events.secret.slots.available_permits(), 0);
    drop(frame);
    assert_eq!(events.pending.lock().unwrap().len(), 1);
    events.flush().await;
    let got = api.received.lock().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0]["count"], 1);
    assert_eq!(got[0]["status"], 502);
    assert_eq!(got[0]["secrets"], json!(["A"]));
}

#[tokio::test]
async fn delivered_event_does_not_release_an_uploads_remaining_context_charge() {
    let (events, _) = setup(1, 32 * 1024).await;
    let audit = admitted(&events, "a.example.com", &["A"]);
    audit.used(vec!["A".into()]);
    audit.arm();
    audit.finish(200);
    let upload = Retained::new(Full::new(Bytes::from_static(b"upload")), audit.clone());
    drop(audit);
    events.flush().await;
    assert_eq!(events.secret.slots.available_permits(), 0);
    drop(upload);
    assert_eq!(events.secret.slots.available_permits(), 1);
    assert!(events.pending.lock().unwrap().is_empty());
}

#[tokio::test]
async fn escaped_and_oversized_metadata_and_plain_events_have_finite_budgets() {
    let (events, _) = setup(8, 4000).await;
    let long_name = "\"\\\n".repeat(2000);
    assert!(
        events
            .admit(
                Some("bq_test"),
                "a.example.com",
                "GET",
                [long_name.as_str()].into_iter()
            )
            .is_err()
    );
    assert_eq!(events.secret.bytes.used(), 0);
    finish(&events, "a.example.com", &["A"]);
    assert!(
        events
            .admit(Some("bq_test"), "b.example.com", "GET", ["B"].into_iter())
            .is_err()
    );
    for index in 0..100 {
        events.record(
            Some("bq_test"),
            &format!("{index}.example.com"),
            "GET",
            200,
            vec![],
        );
    }
    assert!(events.plain.bytes.used() <= 32 * 1024);
    assert!(events.pending.lock().unwrap().len() <= 11);
}

#[tokio::test]
async fn flush_has_finite_batch_counts_and_encoded_bytes_even_with_many_keys() {
    let (events, api) = setup(130, 1024 * 1024).await;
    for index in 0..130 {
        finish(&events, &format!("{index}.example.com"), &["A"]);
    }
    events.flush().await;
    assert_eq!(api.received.lock().unwrap().len(), 130);
    assert!(api.calls.load(Ordering::SeqCst) >= 3);
    assert_eq!(events.secret.bytes.used(), 0);
    assert_eq!(events.secret.slots.available_permits(), 130);
}

#[test]
fn event_keys_do_not_confuse_empty_names_or_delimited_secret_subsets() {
    let event = Event {
        briq_id: Some("bq_test".into()),
        host: "a.example.com".into(),
        method: "GET".into(),
        status: 200,
        secrets: vec![],
        count: 1,
        first_at: "0".into(),
        last_at: "0".into(),
    };
    let mut empty_name = event.clone();
    empty_name.secrets = vec![String::new()];
    assert_ne!(event.key(), empty_name.key());
    let mut joined = event.clone();
    joined.secrets = vec!["A,B".into()];
    let mut separate = event;
    separate.secrets = vec!["A".into(), "B".into()];
    assert_ne!(joined.key(), separate.key());
}
