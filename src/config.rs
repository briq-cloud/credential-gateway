//! What the gateway knows, from the API: the team's secrets (placeholder, value, hosts, where to
//! put them) and the team's briqs (to name the one a request came from). Read at boot and every
//! few seconds, so a rotation or a new secret applies without a restart; the last good config
//! stays when a read fails.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, header};
use http_body_util::{BodyExt, Full, Limited};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Mutex;
use tokio::time::{Instant, sleep, timeout};

use crate::BoxError;

/// A secret as the API sends it.
#[derive(Clone, Debug, Deserialize)]
pub struct Secret {
    pub name: String,
    pub placeholder: String,
    pub value: String,
    #[serde(default)]
    pub hosts: Vec<String>,
    /// `header`, and `body` when the secret allows it.
    #[serde(default)]
    pub locations: Vec<String>,
}

impl Secret {
    pub fn allows(&self, location: &str) -> bool {
        self.locations.iter().any(|l| l == location)
    }
}

#[derive(Deserialize)]
struct BriqEntry {
    id: String,
    host: String,
    /// The team secrets its env names.
    #[serde(default)]
    secrets: Vec<String>,
    /// Its own secrets with hosts, for it alone.
    #[serde(default)]
    own: Vec<Secret>,
}

#[derive(Deserialize)]
struct ConfigDoc {
    #[serde(default)]
    secrets: Vec<Secret>,
    #[serde(default)]
    briqs: Vec<BriqEntry>,
}

/// A host pattern against a host: exact, or `*.example.com` for subdomains only.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let p = pattern.to_ascii_lowercase();
    let h = host.to_ascii_lowercase();
    match p.strip_prefix('*') {
        Some(suffix) if suffix.starts_with('.') => h.ends_with(suffix) && h.len() > suffix.len(),
        _ => p == h,
    }
}

/// An address as the gateway compares them: an IPv4-mapped IPv6 one is the IPv4 one.
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

pub const DEFAULT_API_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// The briq API's `/internal/credential-gateway/*`, with this gateway's token.
pub struct Api {
    url: String,
    token: String,
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    max_response_bytes: usize,
}

impl Api {
    pub fn new(url: &str, token: &str) -> Self {
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_provider_and_webpki_roots(Arc::new(rustls::crypto::ring::default_provider()))
            .expect("the ring provider has safe defaults")
            .https_or_http()
            .enable_http1()
            .build();
        Self {
            url: url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            client: Client::builder(TokioExecutor::new())
                .pool_max_idle_per_host(2)
                .http1_max_buf_size(64 * 1024)
                .build(https),
            max_response_bytes: DEFAULT_API_RESPONSE_BYTES,
        }
    }

    /// Maximum bytes collected from one API response, including chunked responses.
    pub fn with_response_limit(mut self, bytes: usize) -> Self {
        self.max_response_bytes = bytes;
        self
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, BoxError> {
        let mut req = Request::builder()
            .method(method.clone())
            .uri(format!("{}{path}", self.url))
            .header(header::AUTHORIZATION, format!("Bearer {}", self.token));
        let body = match body {
            Some(b) => {
                req = req.header(header::CONTENT_TYPE, "application/json");
                Full::new(Bytes::from(serde_json::to_vec(&b)?))
            }
            None => Full::new(Bytes::new()),
        };
        let work = async {
            let res = self.client.request(req.body(body)?).await?;
            let status = res.status();
            if res
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|n| n > self.max_response_bytes as u64)
            {
                return Err("API response exceeds configured byte limit".into());
            }
            let bytes = Limited::new(res.into_body(), self.max_response_bytes)
                .collect()
                .await?
                .to_bytes();
            if !status.is_success() {
                let text = String::from_utf8_lossy(&bytes[..bytes.len().min(200)]).into_owned();
                return Err(format!("{method} {path}: {} {text}", status.as_u16()).into());
            }
            if bytes.is_empty() {
                return Ok(Value::Null);
            }
            Ok(serde_json::from_slice(&bytes)?)
        };
        timeout(Duration::from_secs(15), work)
            .await
            .map_err(|_| BoxError::from(format!("{method} {path}: no answer in 15 s")))?
    }

    /// Tell the API which certificate this gateway's CA has, so the team's briqs can trust it.
    pub async fn register_ca(&self, cert_pem: &str) -> Result<(), BoxError> {
        let body = serde_json::json!({ "cert": cert_pem });
        self.call(Method::PUT, "/internal/credential-gateway/ca", Some(body))
            .await?;
        Ok(())
    }

    async fn config(&self) -> Result<ConfigDoc, BoxError> {
        let v = self
            .call(Method::GET, "/internal/credential-gateway/config", None)
            .await?;
        Ok(serde_json::from_value(v)?)
    }

    pub async fn events(&self, events: Value) -> Result<(), BoxError> {
        let body = serde_json::json!({ "events": events });
        self.call(
            Method::POST,
            "/internal/credential-gateway/events",
            Some(body),
        )
        .await?;
        Ok(())
    }
}

/// How a briq's host name becomes addresses: DNS, or a stand-in in tests.
pub type Resolve = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send>> + Send + Sync,
>;

/// The system resolver, both families: Fly's private network is IPv6, a briqyard tenant's IPv4.
pub fn dns() -> Resolve {
    Arc::new(|host| {
        Box::pin(async move {
            Ok(tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .map(|a| a.ip())
                .collect())
        })
    })
}

#[derive(Default)]
struct State {
    /// Which read this is: a slower, older read never replaces a newer one.
    generation: u64,
    secrets: Vec<Secret>,
    by_ip: HashMap<IpAddr, String>,
    named: HashMap<String, HashSet<String>>,
    own: HashMap<String, Vec<Secret>>,
}

impl State {
    fn selected<'a>(
        &'a self,
        host: &'a str,
        briq: Option<&'a str>,
    ) -> impl Iterator<Item = &'a Secret> + 'a {
        let named = briq.and_then(|id| self.named.get(id));
        let own = briq
            .filter(|_| named.is_some())
            .and_then(|id| self.own.get(id));
        self.secrets
            .iter()
            .filter(move |s| named.is_some_and(|names| names.contains(&s.name)))
            .chain(own.into_iter().flatten())
            .filter(move |s| s.hosts.iter().any(|p| host_matches(p, host)))
    }
}

/// The live config.
pub struct Config {
    api: Arc<Api>,
    resolve: Resolve,
    unknown_wait: Duration,
    state: RwLock<Arc<State>>,
    reads: AtomicU64,
    /// When the last shared refresh was asked for (`refresh_soon`).
    asked: Mutex<Option<Instant>>,
}

impl Config {
    pub fn new(api: Arc<Api>, resolve: Resolve, unknown_wait: Duration) -> Self {
        Self {
            api,
            resolve,
            unknown_wait,
            state: RwLock::new(Arc::new(State::default())),
            reads: AtomicU64::new(0),
            asked: Mutex::new(None),
        }
    }

    pub async fn refresh(&self) -> Result<(), BoxError> {
        let generation = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
        let doc = self.api.config().await?;
        let lookups = doc.briqs.iter().map(|b| {
            let lookup = (self.resolve)(b.host.clone());
            async move {
                timeout(Duration::from_secs(5), lookup)
                    .await
                    .ok()
                    .and_then(Result::ok)
            }
        });
        let mut by_ip: HashMap<IpAddr, String> = HashMap::new();
        let mut shared = HashSet::new();
        for (b, addrs) in doc
            .briqs
            .iter()
            .zip(futures_util::future::join_all(lookups).await)
        {
            // A briq that is not running has no address; it is not sending requests either.
            for ip in addrs.unwrap_or_default() {
                let ip = normalize_ip(ip);
                match by_ip.get(&ip) {
                    Some(other) if other != &b.id => {
                        shared.insert(ip);
                    }
                    _ => {
                        by_ip.insert(ip, b.id.clone());
                    }
                }
            }
        }
        // An address two briqs claim (one gone, its address given again, a name not yet
        // updated) is nobody's: its requests get no secrets until it is one briq's again.
        for ip in &shared {
            by_ip.remove(ip);
            crate::log!(Warn, "an address two briqs claim gets no secrets", "address": ip.to_string());
        }
        let state = State {
            generation,
            secrets: doc.secrets,
            named: doc
                .briqs
                .iter()
                .map(|b| (b.id.clone(), b.secrets.iter().cloned().collect()))
                .collect(),
            own: doc.briqs.into_iter().map(|b| (b.id, b.own)).collect(),
            by_ip,
        };
        crate::log!(Debug, "config refreshed", "secrets": state.secrets.len(), "briqs": state.by_ip.len());
        let mut current = self.state.write().unwrap();
        if generation > current.generation {
            *current = Arc::new(state);
        }
        Ok(())
    }

    /// The first read, then one every `every`, for as long as the process runs.
    pub async fn start(self: &Arc<Self>, every: Duration) {
        if let Err(err) = self.refresh().await {
            crate::log!(Warn, "config refresh failed", "err": err.to_string());
        }
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                sleep(every).await;
                if let Err(err) = me.refresh().await {
                    crate::log!(Warn, "config refresh failed", "err": err.to_string());
                }
            }
        });
    }

    /// The secrets that apply to a request from `briq` to `host`: the ones that briq named in its
    /// env, and its own, for that host. Naming a secret at run is the grant; a request from no
    /// known briq gets none, and another briq's placeholder passes through as text.
    pub fn for_host(&self, host: &str, briq: Option<&str>) -> Vec<Secret> {
        self.for_host_with(host, briq, |_| Ok::<_, std::convert::Infallible>(()))
            .unwrap()
            .0
    }

    /// CONNECT needs only an existence check, never an unbudgeted copy of secret values.
    pub fn has_for_host(&self, host: &str, briq: Option<&str>) -> bool {
        self.state
            .read()
            .unwrap()
            .selected(host, briq)
            .next()
            .is_some()
    }

    /// Admit a borrowed selection before copying any secret values. The same locked config
    /// generation supplies the estimate and the owned values, including after a rotation.
    pub fn for_host_with<T, E>(
        &self,
        host: &str,
        briq: Option<&str>,
        admit: impl FnOnce(&mut dyn Iterator<Item = &Secret>) -> Result<T, E>,
    ) -> Result<(Vec<Secret>, T), E> {
        let state = self.state.read().unwrap();
        let permit = admit(&mut state.selected(host, briq))?;
        Ok((state.selected(host, briq).cloned().collect(), permit))
    }

    /// Which briq an address belongs to, when the API told us about it.
    pub fn briq_of(&self, ip: IpAddr) -> Option<String> {
        self.state
            .read()
            .unwrap()
            .by_ip
            .get(&normalize_ip(ip))
            .cloned()
    }

    /// `briq_of`, asking the API again while the address is new to us, for up to the unknown
    /// wait: a briq that just booted makes its first requests before the next refresh, and its
    /// name can take a few seconds more to resolve. Still unknown after that: no briq.
    pub async fn resolve_briq(&self, ip: IpAddr) -> Option<String> {
        let deadline = Instant::now() + self.unknown_wait;
        loop {
            let known = self.briq_of(ip);
            if known.is_some() || Instant::now() >= deadline {
                return known;
            }
            // A slow API or resolver does not hold the connection past its wait.
            let _ = tokio::time::timeout_at(deadline, self.refresh_soon()).await;
        }
    }

    /// A refresh shared by every connection waiting on one, at most one a second.
    async fn refresh_soon(&self) {
        let started = Instant::now();
        let mut asked = self.asked.lock().await;
        if let Some(at) = *asked {
            if at >= started {
                // Another connection refreshed while this one waited for the lock.
                return;
            }
            sleep((at + Duration::from_secs(1)).saturating_duration_since(Instant::now())).await;
        }
        *asked = Some(Instant::now());
        if let Err(err) = self.refresh().await {
            crate::log!(Warn, "config refresh failed", "err": err.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_exact_hosts_and_wildcard_subdomains() {
        assert!(host_matches("api.github.com", "api.github.com"));
        assert!(host_matches("API.github.com", "api.GITHUB.com"));
        assert!(!host_matches("api.github.com", "github.com"));
        assert!(host_matches("*.example.com", "a.example.com"));
        assert!(host_matches("*.example.com", "a.b.example.com"));
        assert!(!host_matches("*.example.com", "example.com"));
        assert!(!host_matches("*.example.com", "notexample.com"));
        assert!(!host_matches("*example.com", "notexample.com"));
    }

    #[test]
    fn reads_an_ipv4_mapped_address_as_ipv4() {
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert_eq!(normalize_ip(mapped), "127.0.0.1".parse::<IpAddr>().unwrap());
        let v6: IpAddr = "fdaa::1".parse().unwrap();
        assert_eq!(normalize_ip(v6), v6);
    }
}
