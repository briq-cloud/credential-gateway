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
use std::sync::Arc;
use std::time::Duration;

use async_compression::tokio::bufread::{
    BrotliDecoder, DeflateDecoder, GzipDecoder, ZlibDecoder, ZstdDecoder,
};
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
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use tokio::io::{AsyncBufReadExt, AsyncRead};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_util::io::{ReaderStream, StreamReader};

use crate::BoxError;
use crate::ca::Leafs;
use crate::config::{Config, Secret};
use crate::events::Events;
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
    /// CAs trusted for destinations besides the public roots (tests).
    pub upstream_ca: Vec<CertificateDer<'static>>,
    /// The port intercepted requests are sent to instead of the CONNECT port (tests).
    pub upstream_port: Option<u16>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_body: 8 * 1024 * 1024,
            upstream_ca: Vec::new(),
            upstream_port: None,
        }
    }
}

pub struct Gateway {
    config: Arc<Config>,
    leafs: Arc<Leafs>,
    events: Arc<Events>,
    opts: Options,
    upstream: Client<HttpsConnector<HttpConnector>, Body>,
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
            leafs,
            events,
            opts,
            upstream: Client::builder(TokioExecutor::new()).build(https),
            plain: Client::builder(TokioExecutor::new()).build(plain),
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
            let _ = stream.set_nodelay(true);
            let gw = self.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| {
                    let gw = gw.clone();
                    async move { Ok::<_, Infallible>(gw.outer(req, peer).await) }
                });
                let _ = http1::Builder::new()
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
        let secrets = if port == 443 {
            self.config.for_host(&host, briq.as_deref())
        } else {
            Vec::new()
        };
        if secrets.is_empty() {
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
        let secrets = Arc::new(secrets);
        tokio::spawn(async move {
            let Ok(upgraded) = on_upgrade.await else {
                return;
            };
            let stream = match tls.accept(TokioIo::new(upgraded)).await {
                Ok(s) => s,
                Err(err) => {
                    crate::log!(Debug, "client TLS handshake failed", "host": host, "err": err.to_string());
                    return;
                }
            };
            let svc = service_fn(move |req| {
                let (gw, host, secrets, briq) =
                    (self.clone(), host.clone(), secrets.clone(), briq.clone());
                async move {
                    let res = match gw
                        .intercept(req, &host, port, &secrets, briq.as_deref())
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
                .serve_connection(TokioIo::new(stream), svc)
                .await;
        });
        empty(StatusCode::OK)
    }

    /// One request to an intercepted host.
    async fn intercept(
        &self,
        req: Request<Incoming>,
        host: &str,
        port: u16,
        secrets: &[Secret],
        briq: Option<&str>,
    ) -> Result<Response<Body>, BoxError> {
        // The request must address the CONNECT host: a Host naming another site on the same
        // address (a shared CDN) would carry the real value there. An absolute-form target is
        // refused too.
        let req_host = req
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(|h| strip_port(h).to_ascii_lowercase());
        if req_host.is_some_and(|h| h != host.to_ascii_lowercase()) || req.uri().scheme().is_some()
        {
            return Ok(text(
                StatusCode::BAD_REQUEST,
                &format!("briq credential gateway: the request must address {host}\n"),
            ));
        }
        let (parts, body) = req.into_parts();
        let mut headers = forward_headers(&parts.headers);
        headers.insert(header::HOST, HeaderValue::from_str(host)?);
        // Scrubbing reads the response: ask for it uncompressed.
        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );

        let mut used: Vec<String> = Vec::new();
        // Headers: every secret that allows them.
        let in_headers: Vec<&Secret> = secrets.iter().filter(|s| s.allows("header")).collect();
        if let Some(r) = replacer(&in_headers, |s| (&s.placeholder, &s.value)) {
            for v in headers.values_mut() {
                let (out, hits) = r.replace_all(v.as_bytes());
                if hits.iter().any(|h| *h) {
                    *v = HeaderValue::from_bytes(&out)
                        .map_err(|_| "a secret's value cannot go in a header")?;
                    used.extend(names(&in_headers, &hits));
                }
            }
        }

        // The body, for the secrets that allow it: held up to `max_body` to keep its length,
        // rewritten as it streams past that. Without such a secret it goes on untouched.
        let in_body: Vec<&Secret> = secrets.iter().filter(|s| s.allows("body")).collect();
        let mut body_hits = None;
        let body: Body = match replacer(&in_body, |s| (&s.placeholder, &s.value)) {
            None => boxed(body),
            Some(r) => {
                let r = Arc::new(r);
                let (head, rest) = read_up_to(body, self.opts.max_body).await?;
                match rest {
                    None => {
                        let (out, hits) = r.replace_all(&head);
                        used.extend(names(&in_body, &hits));
                        // A request that had no body (a GET) is sent without one.
                        let had_body = !out.is_empty()
                            || parts.headers.contains_key(header::CONTENT_LENGTH)
                            || parts.headers.contains_key(header::TRANSFER_ENCODING);
                        if had_body {
                            headers.insert(header::CONTENT_LENGTH, out.len().into());
                        }
                        full(out)
                    }
                    Some(rest) => {
                        headers.remove(header::CONTENT_LENGTH);
                        let stream = Stream::new(r);
                        body_hits = Some(stream.hits());
                        let chained = StreamBody::new(
                            futures_util::stream::once(async move {
                                Ok::<_, BoxError>(Frame::data(head.freeze()))
                            })
                            .chain(TryStreamExt::map_err(BodyStream::new(rest), BoxError::from)),
                        );
                        Rewrite::new(chained, stream).boxed_unsync()
                    }
                }
            }
        };

        let port = self.opts.upstream_port.unwrap_or(port);
        let path = parts
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let mut up = Request::builder()
            .method(parts.method.clone())
            .uri(Uri::try_from(format!("https://{host}:{port}{path}"))?)
            .body(body)?;
        *up.headers_mut() = headers;
        let res = self.upstream.request(up).await?;
        if let Some(h) = &body_hits {
            used.extend(
                in_body
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| h.get(*i))
                    .map(|(_, s)| s.name.clone()),
            );
        }
        self.events.record(
            briq,
            host,
            parts.method.as_str(),
            res.status().as_u16(),
            used,
        );

        // What comes back: a real value, if the destination echoes it, becomes the placeholder
        // again, in headers and body. Every secret that applies to this request, used or not.
        let scrub = Arc::new(
            replacer(&secrets.iter().collect::<Vec<_>>(), |s| {
                (&s.value, &s.placeholder)
            })
            .ok_or("no secret to scrub")?,
        );
        let (parts_res, body) = res.into_parts();
        let mut out = Response::builder()
            .status(parts_res.status)
            .body(Empty::new().map_err(never).boxed_unsync())?;
        let mut headers = forward_headers(&parts_res.headers);
        for v in headers.values_mut() {
            let (o, hits) = scrub.replace_all(v.as_bytes());
            if hits.iter().any(|h| *h) {
                *v = HeaderValue::from_bytes(&o)?;
            }
        }
        let st = parts_res.status;
        if parts.method == Method::HEAD
            || st.is_informational()
            || st == StatusCode::NO_CONTENT
            || st == StatusCode::NOT_MODIFIED
        {
            *out.headers_mut() = headers;
            return Ok(out);
        }
        // The length changes with what is replaced: the body goes out chunked.
        headers.remove(header::CONTENT_LENGTH);
        let encoding = headers
            .get(header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty() && v != "identity");
        let body: Body = match encoding {
            None => boxed(body),
            // Asked for none, got a compressed body: read it to scrub it, or refuse it. A real
            // value never goes on unread.
            Some(enc) => match decoded(body, &enc).await {
                Some(b) => {
                    headers.remove(header::CONTENT_ENCODING);
                    b
                }
                None => {
                    return Ok(text(
                        StatusCode::BAD_GATEWAY,
                        &format!(
                            "briq credential gateway: a {enc} response from {host} could not be read to scrub it\n"
                        ),
                    ));
                }
            },
        };
        *out.headers_mut() = headers;
        *out.body_mut() = Rewrite::new(body, Stream::new(scrub)).boxed_unsync();
        Ok(out)
    }

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

/// A compressed body, decompressed as it streams: one encoding, the usual ones.
async fn decoded(body: Incoming, encoding: &str) -> Option<Body> {
    let mut reader = StreamReader::new(BodyDataStream::new(body).map_err(io::Error::other));
    let read: Box<dyn AsyncRead + Send + Unpin> = match encoding {
        "gzip" | "x-gzip" => {
            let mut d = GzipDecoder::new(reader);
            d.multiple_members(true);
            Box::new(d)
        }
        // A zlib stream, or raw deflate from servers that send that instead.
        "deflate" => {
            let head = reader.fill_buf().await.ok()?;
            let zlib = head.len() >= 2
                && head[0] & 0x0f == 8
                && ((u16::from(head[0]) << 8) | u16::from(head[1])) % 31 == 0;
            if zlib {
                Box::new(ZlibDecoder::new(reader))
            } else {
                Box::new(DeflateDecoder::new(reader))
            }
        }
        "br" => Box::new(BrotliDecoder::new(reader)),
        "zstd" => Box::new(ZstdDecoder::new(reader)),
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
) -> Option<Replacer> {
    let pairs: Vec<(&String, &String)> = secrets.iter().map(|s| pick(s)).collect();
    Replacer::new(&pairs)
}

fn names(secrets: &[&Secret], hits: &[bool]) -> Vec<String> {
    secrets
        .iter()
        .zip(hits)
        .filter(|(_, h)| **h)
        .map(|(s, _)| s.name.clone())
        .collect()
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
