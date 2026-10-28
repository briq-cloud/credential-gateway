//! The briq credential gateway, as a briq runs it: one per team, on the team's private network.
//!   BRIQ_API_URL        the API that holds the team's secrets (https://api.briq.cloud)
//!   BRIQ_GATEWAY_TOKEN  this gateway's bearer token for the API's /internal/credential-gateway/*
//!   BRIQ_TEAM           what a new CA says it is for
//!   GATEWAY_PORT        3128 unless set
//!   GATEWAY_STATE_DIR   where the CA lives, a volume (/data)
//!   GATEWAY_REFRESH_MS  how often the config is read again (15000)
//!   GATEWAY_LOG_LEVEL   debug, info (default), warn, error
//!
//! `credential-gateway health` asks a running gateway's /healthz: exit 0 when it answers.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use credential_gateway::ca::{Ca, Leafs};
use credential_gateway::config::{Api, Config, dns};
use credential_gateway::events::Events;
use credential_gateway::log;
use credential_gateway::proxy::{Gateway, Options};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal::unix::{SignalKind, signal};

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn port() -> u16 {
    env("GATEWAY_PORT")
        .and_then(|p| p.parse().ok())
        .unwrap_or(3128)
}

#[tokio::main]
async fn main() {
    if std::env::args().nth(1).as_deref() == Some("health") {
        std::process::exit(if health(port()).await { 0 } else { 1 });
    }
    log::set_level(&env("GATEWAY_LOG_LEVEL").unwrap_or_default());
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (Some(api_url), Some(token)) = (env("BRIQ_API_URL"), env("BRIQ_GATEWAY_TOKEN")) else {
        credential_gateway::log!(Error, "BRIQ_API_URL and BRIQ_GATEWAY_TOKEN are required");
        std::process::exit(2);
    };
    let state_dir = PathBuf::from(env("GATEWAY_STATE_DIR").unwrap_or_else(|| "/data".into()));
    let refresh = Duration::from_millis(
        env("GATEWAY_REFRESH_MS")
            .and_then(|v| v.parse().ok())
            .unwrap_or(15_000),
    );

    let ca = match Ca::load_or_create(
        &state_dir,
        &env("BRIQ_TEAM").unwrap_or_else(|| "team".into()),
    ) {
        Ok(ca) => ca,
        Err(err) => {
            credential_gateway::log!(Error, "the CA cannot be read; not replacing it", "err": err);
            std::process::exit(1);
        }
    };
    let api = Arc::new(Api::new(&api_url, &token));
    if let Err(err) = api.register_ca(&ca.cert_pem).await {
        credential_gateway::log!(Error, "the CA could not be registered", "err": err.to_string());
        std::process::exit(1);
    }
    credential_gateway::log!(Info, "ca registered", "subject": ca.subject);

    let config = Arc::new(Config::new(api.clone(), dns(), Duration::from_secs(10)));
    config.start(refresh).await;
    let events = Events::new(api);
    events.start(Duration::from_secs(30));
    let leafs = match Leafs::new(ca) {
        Ok(l) => Arc::new(l),
        Err(err) => {
            credential_gateway::log!(Error, "no leaf key", "err": err);
            std::process::exit(1);
        }
    };
    let gateway = Gateway::new(config, leafs, events.clone(), Options::default());

    let port = port();
    let listener = match TcpListener::bind(("::", port)).await {
        Ok(l) => l,
        Err(err) => {
            credential_gateway::log!(Error, "cannot listen", "port": port, "err": err.to_string());
            std::process::exit(1);
        }
    };
    credential_gateway::log!(Info, "listening", "port": port);
    let server = tokio::spawn(gateway.serve(listener));

    let mut term = signal(SignalKind::terminate()).expect("a SIGTERM handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
        _ = server => {}
    }
    events.flush().await;
}

async fn health(port: u16) -> bool {
    let check = async {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.ok()?;
        s.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .ok()?;
        let mut buf = [0u8; 12];
        s.read_exact(&mut buf).await.ok()?;
        Some(buf.starts_with(b"HTTP/1.1 200"))
    };
    tokio::time::timeout(Duration::from_secs(5), check)
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}
