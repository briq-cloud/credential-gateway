//! The proxy. A briq points HTTPS_PROXY at it. For a CONNECT to a host one of the calling briq's
//! secrets allows, the gateway answers the TLS handshake itself with a certificate from its CA,
//! reads the requests, swaps each placeholder for the real value where the secret allows (headers,
//! body), sends them on over its own TLS connection, and rewrites the real value back to the
//! placeholder in what comes back. Both directions stream. Any other host is tunnelled byte for
//! byte: the gateway sees nothing of it.
//! Plain HTTP through the proxy is forwarded as it is, never injected: a real value in clear is
//! not something we send.

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_compression::tokio::bufread::{DeflateDecoder, GzipDecoder, ZlibDecoder};
use bytes::{Bytes, BytesMut};
use futures_util::{StreamExt, TryStreamExt};
use http::header::{self, HeaderMap, HeaderValue};
use http::{Method, Request, Response, StatusCode, Uri};
use http_body::Frame;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyDataStream, BodyExt, BodyStream, Empty, Full, StreamBody};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsAcceptor;
use tokio_util::io::{ReaderStream, StreamReader};

use crate::BoxError;

mod intercept;
use crate::budget::{Budget, DEFAULT_REWRITE_BUDGET, estimate};
use crate::ca::Leafs;
use crate::config::{Config, Secret};
use crate::events::Events;
use crate::retained::Retained;
use crate::rewrite::{Replacer, Rewrite, Stream};

pub type Body = UnsyncBoxBody<Bytes, BoxError>;

/// Hop-by-hop headers, never forwarded.
const HOP: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub struct Options {
    /// A request body to put secrets in is held up to this size, to send it with its length;
    /// a larger one is rewritten as it streams and sent chunked.
    pub max_body: usize,
    /// Maximum bodies buffered at once; zero streams every body.
    pub held_bodies: usize,
    /// Maximum accepted proxy sockets, including headers, upgrades and tunnels.
    pub max_connections: usize,
    /// Global estimated matcher construction/retention budget; excess requests get 503.
    pub rewrite_budget: usize,
    /// Maximum time for a client to complete TLS after CONNECT.
    pub handshake_timeout: Duration,
    /// CAs trusted for destinations besides the public roots (tests).
    pub upstream_ca: Vec<CertificateDer<'static>>,
    /// The port intercepted requests are sent to instead of the CONNECT port (tests).
    pub upstream_port: Option<u16>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_body: 8 * 1024 * 1024,
            held_bodies: 8,
            max_connections: 1024,
            rewrite_budget: DEFAULT_REWRITE_BUDGET,
            handshake_timeout: Duration::from_secs(10),
            upstream_ca: Vec::new(),
            upstream_port: None,
        }
    }
}

/// How long a client has to send a request's headers, the next one on a kept-alive connection
/// included.
const HEADER_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_HEADER_BYTES: usize = 64 * 1024;
const HEALTH_CONNECTIONS: usize = 2;
const HEALTH_TIMEOUT: Duration = Duration::from_secs(2);

/// The admission permit follows the socket when Hyper transfers it into an upgrade.
/// Holding it in the outer HTTP task would release it before TLS or a tunnel finishes.
struct LimitedSocket {
    stream: TcpStream,
    _permit: OwnedSemaphorePermit,
}

impl AsyncRead for LimitedSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for LimitedSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
}

/// Only the local health command may use the reserve; it cannot proxy or keep a socket alive.
async fn reserved_health(stream: LimitedSocket) {
    let svc = service_fn(|req: Request<Incoming>| async move {
        let res = if req.method() == Method::GET
            && req.uri().path() == "/healthz"
            && req.uri().scheme().is_none()
        {
            text(StatusCode::OK, "ok\n")
        } else {
            status(StatusCode::SERVICE_UNAVAILABLE)
        };
        Ok::<_, Infallible>(res)
    });
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(HEALTH_TIMEOUT)
        .max_buf_size(MAX_HEADER_BYTES)
        .max_headers(16)
        .keep_alive(false);
    let _ = tokio::time::timeout(
        HEALTH_TIMEOUT,
        builder.serve_connection(TokioIo::new(stream), svc),
    )
    .await;
}

pub struct Gateway {
    config: Arc<Config>,
    held: Arc<Semaphore>,
    rewrite_budget: Arc<Budget>,
    connections: Arc<Semaphore>,
    health_connections: Arc<Semaphore>,
    leafs: Arc<Leafs>,
    events: Arc<Events>,
    opts: Options,
    upstream_connector: HttpsConnector<HttpConnector>,
    plain: Client<HttpConnector, Body>,
}

impl Gateway {
    pub fn new(
        config: Arc<Config>,
        leafs: Arc<Leafs>,
        events: Arc<Events>,
        opts: Options,
    ) -> Arc<Self> {
        let mut roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        for ca in &opts.upstream_ca {
            let _ = roots.add(ca.clone());
        }
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("the ring provider has safe defaults")
        .with_root_certificates(roots)
        .with_no_client_auth();
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_connect_timeout(Some(Duration::from_secs(10)));
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_only()
            .enable_http1()
            .wrap_connector(http.clone());
        let mut plain = HttpConnector::new();
        plain.set_connect_timeout(Some(Duration::from_secs(10)));
        Arc::new(Self {
            config,
            held: Arc::new(Semaphore::new(opts.held_bodies)),
            rewrite_budget: Budget::new(opts.rewrite_budget),
            connections: Arc::new(Semaphore::new(opts.max_connections)),
            health_connections: Arc::new(Semaphore::new(HEALTH_CONNECTIONS)),
            leafs,
            events,
            opts,
            upstream_connector: https,
            plain: Client::builder(TokioExecutor::new())
                .pool_max_idle_per_host(0)
                .http1_max_buf_size(MAX_HEADER_BYTES)
                .build(plain),
        })
    }

    /// Serves connections from `listener` until the process ends.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(c) => c,
                Err(err) => {
                    crate::log!(Warn, "accept failed", "err": err.to_string());
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let (permit, health_only) = match self.connections.clone().try_acquire_owned() {
                Ok(permit) => (permit, false),
                Err(_) => {
                    // The binary health check connects to 127.0.0.1. IPv4 clients of the
                    // IPv6 listener arrive as mapped addresses, so canonicalize first.
                    if !peer.ip().to_canonical().is_loopback() {
                        continue;
                    }
                    match self.health_connections.clone().try_acquire_owned() {
                        Ok(permit) => (permit, true),
                        Err(_) => continue,
                    }
                }
            };
            let _ = stream.set_nodelay(true);
            let stream = LimitedSocket {
                stream,
                _permit: permit,
            };
            if health_only {
                tokio::spawn(reserved_health(stream));
                continue;
            }
            let gw = self.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| {
                    let gw = gw.clone();
                    async move { Ok::<_, Infallible>(gw.outer(req, peer).await) }
                });
                let _ = http1::Builder::new()
                    .timer(TokioTimer::new())
                    .header_read_timeout(HEADER_TIMEOUT)
                    .max_buf_size(MAX_HEADER_BYTES)
                    .serve_connection(TokioIo::new(stream), svc)
                    .with_upgrades()
                    .await;
            });
        }
    }

    /// A request to the proxy itself.
    async fn outer(self: Arc<Self>, req: Request<Incoming>, peer: SocketAddr) -> Response<Body> {
        if req.method() == Method::CONNECT {
            return self.connect(req, peer).await;
        }
        // Health, for the machine's check.
        if req.uri().path() == "/healthz" && req.uri().scheme().is_none() {
            return text(StatusCode::OK, "ok\n");
        }
        // Plain HTTP through the proxy: forwarded, never injected.
        match req.uri().scheme_str() {
            Some("http") => self.forward_plain(req).await,
            Some(_) => text(
                StatusCode::BAD_REQUEST,
                "plain HTTP only here; use CONNECT for TLS\n",
            ),
            None => text(
                StatusCode::BAD_REQUEST,
                "a proxy request needs an absolute URL\n",
            ),
        }
    }

    async fn connect(self: Arc<Self>, req: Request<Incoming>, peer: SocketAddr) -> Response<Body> {
        let Some(auth) = req.uri().authority().cloned() else {
            return status(StatusCode::BAD_REQUEST);
        };
        let host = auth
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let port = auth.port_u16().unwrap_or(443);
        let briq = self.config.resolve_briq(peer.ip()).await;
        // Every briq that goes through the gateway is in its config; an address none has is
        // tunnelled without secrets, and says so.
        if briq.is_none() {
            crate::log!(Warn, "request from an unknown address, tunnelled without secrets",
                "address": peer.ip().to_string(), "host": host);
        }
        // Whether to intercept is decided here; which secrets apply is read again for each
        // request, so a revoked or rotated secret stops at the next one, kept-alive or not.
        if port != 443 || !self.config.has_for_host(&host, briq.as_deref()) {
            return tunnel(req, &host, port).await;
        }
        let tls = match self.leafs.for_host(&host) {
            Ok(cfg) => TlsAcceptor::from(cfg),
            Err(err) => {
                crate::log!(Warn, "no certificate for the host", "host": host, "err": err);
                return status(StatusCode::BAD_GATEWAY);
            }
        };
        let on_upgrade = hyper::upgrade::on(req);
        tokio::spawn(async move {
            let Ok(upgraded) = on_upgrade.await else {
                return;
            };
            let stream = match tokio::time::timeout(
                self.opts.handshake_timeout,
                tls.accept(TokioIo::new(upgraded)),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Err(_) => {
                    crate::log!(Debug, "client TLS handshake timed out", "host": host);
                    return;
                }
                Ok(Err(err)) => {
                    crate::log!(Debug, "client TLS handshake failed", "host": host, "err": err.to_string());
                    return;
                }
            };
            // Only this CONNECT session owns its fixed-host pool. Dropping the session
            // closes idle upstream sockets instead of retaining them past admission release.
            let upstream = Client::builder(TokioExecutor::new())
                .pool_max_idle_per_host(1)
                .http1_max_buf_size(MAX_HEADER_BYTES)
                .build(self.upstream_connector.clone());
            let svc = service_fn(move |req| {
                let (gw, host, briq) = (self.clone(), host.clone(), briq.clone());
                let upstream = upstream.clone();
                async move {
                    let res = match gw
                        .intercept(req, &host, port, briq.as_deref(), &upstream)
                        .await
                    {
                        Ok(res) => res,
                        Err(err) => {
                            crate::log!(Warn, "request failed", "host": host, "err": err.to_string());
                            status(StatusCode::BAD_GATEWAY)
                        }
                    };
                    Ok::<_, Infallible>(res)
                }
            });
            let _ = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_TIMEOUT)
                .max_buf_size(MAX_HEADER_BYTES)
                .serve_connection(TokioIo::new(stream), svc)
                .await;
        });
        empty(StatusCode::OK)
    }

    /// One request to an intercepted host.
    async fn forward_plain(&self, req: Request<Incoming>) -> Response<Body> {
        let (parts, body) = req.into_parts();
        let host = parts
            .uri
            .authority()
            .map(|a| a.to_string())
            .unwrap_or_default();
        let mut headers = forward_headers(&parts.headers);
        if let Ok(h) = HeaderValue::from_str(&host) {
            headers.insert(header::HOST, h);
        }
        let mut up = Request::new(boxed(body));
        *up.method_mut() = parts.method;
        *up.uri_mut() = parts.uri;
        *up.headers_mut() = headers;
        match self.plain.request(up).await {
            Ok(res) => {
                let (p, b) = res.into_parts();
                let mut out = Response::new(boxed(b));
                *out.status_mut() = p.status;
                *out.headers_mut() = forward_headers(&p.headers);
                out
            }
            Err(err) => {
                crate::log!(Warn, "http forward failed", "host": host, "err": err.to_string());
                status(StatusCode::BAD_GATEWAY)
            }
        }
    }
}

/// A host the gateway has nothing to put in for: a tunnel.
async fn tunnel(req: Request<Incoming>, host: &str, port: u16) -> Response<Body> {
    let connect = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((host, port)));
    let mut up = match connect.await {
        Ok(Ok(s)) => s,
        Ok(Err(err)) => {
            crate::log!(Debug, "tunnel failed", "host": host, "port": port, "err": err.to_string());
            return status(StatusCode::BAD_GATEWAY);
        }
        Err(_) => {
            crate::log!(Debug, "tunnel failed", "host": host, "port": port, "err": "connect timed out");
            return status(StatusCode::BAD_GATEWAY);
        }
    };
    let _ = up.set_nodelay(true);
    let on_upgrade = hyper::upgrade::on(req);
    tokio::spawn(async move {
        if let Ok(upgraded) = on_upgrade.await {
            let _ = tokio::io::copy_bidirectional(&mut TokioIo::new(upgraded), &mut up).await;
        }
    });
    empty(StatusCode::OK)
}

/// The headers to send on: not the hop-by-hop ones, nor those `Connection` names, nor `Host`.
fn forward_headers(from: &HeaderMap) -> HeaderMap {
    let named: Vec<String> = from
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(|t| t.trim().to_ascii_lowercase()))
        .collect();
    let mut out = HeaderMap::with_capacity(from.len());
    for (name, value) in from {
        let n = name.as_str();
        if HOP.contains(&n) || n == "host" || named.iter().any(|x| x == n) {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

/// The whole body up to `max` bytes; past it, what was read and the rest still to come.
async fn read_up_to(
    mut body: Incoming,
    max: usize,
) -> Result<(BytesMut, Option<Incoming>), BoxError> {
    let mut buf = BytesMut::new();
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame?.into_data() {
            buf.extend_from_slice(&data);
            if buf.len() > max {
                return Ok((buf, Some(body)));
            }
        }
    }
    Ok((buf, None))
}

/// Contradictory hop-by-hop metadata is refused before looking at or decoding a body.
fn response_encoding(headers: &HeaderMap) -> Result<Option<String>, BoxError> {
    if headers.get_all(header::CONNECTION).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|name| name.trim().eq_ignore_ascii_case("content-encoding"))
        })
    }) {
        return Err("Connection nominates Content-Encoding".into());
    }
    let mut encoding = None;
    for value in headers.get_all(header::CONTENT_ENCODING) {
        for coding in value.to_str()?.split(',').map(str::trim) {
            if coding.is_empty() || coding.eq_ignore_ascii_case("identity") {
                continue;
            }
            let coding = coding.to_ascii_lowercase();
            if encoding.is_some() || !matches!(coding.as_str(), "gzip" | "x-gzip" | "deflate") {
                return Err("unsupported response encoding".into());
            }
            encoding = Some(coding);
        }
    }
    Ok(encoding)
}

fn encoding_refusal() -> Response<Body> {
    text(
        StatusCode::BAD_GATEWAY,
        "credential gateway: response encoding cannot be read to scrub it\n",
    )
}

/// A compressed body, decompressed as it streams: one encoding, the usual ones.
async fn decoded<B>(body: B, encoding: &str) -> Option<Body>
where
    B: http_body::Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    // These codings may request decoder windows larger than a small gateway's memory.
    // Refuse them (and every unknown coding) before constructing a body reader or decoder.
    if !matches!(encoding, "gzip" | "x-gzip" | "deflate") {
        return None;
    }
    let mut reader = StreamReader::new(BodyDataStream::new(body).map_err(io::Error::other));
    let read: Box<dyn AsyncRead + Send + Unpin> = match encoding {
        "gzip" | "x-gzip" => {
            let mut d = GzipDecoder::new(reader);
            d.multiple_members(true);
            Box::new(d)
        }
        // A zlib stream, or raw deflate from servers that send that instead.
        "deflate" => {
            // fill_buf may expose only one network frame. Read the two-byte signature
            // completely, then prepend it without dropping or copying the remaining stream.
            let mut head = [0; 2];
            reader.read_exact(&mut head).await.ok()?;
            let zlib =
                head[0] & 0x0f == 8 && ((u16::from(head[0]) << 8) | u16::from(head[1])) % 31 == 0;
            let reader = std::io::Cursor::new(head).chain(reader);
            if zlib {
                Box::new(ZlibDecoder::new(reader))
            } else {
                Box::new(DeflateDecoder::new(reader))
            }
        }
        _ => return None,
    };
    let frames = ReaderStream::new(read)
        .map_ok(Frame::data)
        .map_err(BoxError::from);
    Some(StreamBody::new(frames).boxed_unsync())
}

fn replacer<'a>(
    secrets: &[&'a Secret],
    pick: impl Fn(&'a Secret) -> (&'a String, &'a String),
) -> Result<Option<Replacer>, BoxError> {
    let pairs: Vec<(&String, &String)> = secrets.iter().map(|s| pick(s)).collect();
    Replacer::new(&pairs)
}

/// Check aggregate rewritten size before allocating any header output.
fn rewrite_headers(headers: &mut HeaderMap, replacer: &Replacer) -> Result<Vec<bool>, BoxError> {
    rewrite_headers_except_basic(headers, replacer, false)
}

fn rewrite_headers_except_basic(
    headers: &mut HeaderMap,
    replacer: &Replacer,
    protect_basic: bool,
) -> Result<Vec<bool>, BoxError> {
    let mut size = 2usize;
    for (name, value) in headers.iter() {
        let len = if protect_basic && name == header::AUTHORIZATION {
            value.len()
        } else {
            replacer
                .replaced_len(value.as_bytes(), MAX_HEADER_BYTES)
                .ok_or("rewritten headers exceed 64 KiB")?
        };
        size = size
            .checked_add(name.as_str().len())
            .and_then(|n| n.checked_add(4))
            .and_then(|n| n.checked_add(len))
            .filter(|&n| n <= MAX_HEADER_BYTES)
            .ok_or("rewritten headers exceed 64 KiB")?;
    }
    let mut hits = vec![false; replacer.patterns()];
    for (name, value) in headers.iter_mut() {
        if protect_basic && name == header::AUTHORIZATION {
            continue;
        }
        let (out, matched) = replacer.replace_all(value.as_bytes());
        if matched.iter().any(|&hit| hit) {
            *value = HeaderValue::from_bytes(&out)?;
            for (hit, matched) in hits.iter_mut().zip(matched) {
                *hit |= matched;
            }
        }
    }
    Ok(hits)
}

fn names(secrets: &[&Secret], hits: &[bool]) -> Vec<String> {
    secrets
        .iter()
        .zip(hits)
        .filter(|(_, h)| **h)
        .map(|(s, _)| s.name.clone())
        .collect()
}

/// A host as it goes in a URI or a Host header: an IPv6 address in brackets.
fn bracketed(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host
            .split(']')
            .next()
            .map(|h| h.trim_start_matches('['))
            .unwrap_or(host);
    }
    match host.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host,
    }
}

fn never(n: Infallible) -> BoxError {
    match n {}
}

fn boxed(b: Incoming) -> Body {
    b.map_err(BoxError::from).boxed_unsync()
}

fn full(b: impl Into<Bytes>) -> Body {
    Full::new(b.into()).map_err(never).boxed_unsync()
}

fn empty(code: StatusCode) -> Response<Body> {
    let mut r = Response::new(Empty::new().map_err(never).boxed_unsync());
    *r.status_mut() = code;
    r
}

fn status(code: StatusCode) -> Response<Body> {
    let mut r = Response::new(full(Bytes::new()));
    *r.status_mut() = code;
    r
}

fn text(code: StatusCode, body: &str) -> Response<Body> {
    let mut r = Response::new(full(body.to_string()));
    *r.status_mut() = code;
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    r
}

#[cfg(test)]
#[path = "proxy/encoding_tests.rs"]
mod encoding_tests;
