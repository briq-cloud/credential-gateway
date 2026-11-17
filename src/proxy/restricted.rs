//! The restricted gateway: with a birth egress policy, only a CONNECT to one of its exact
//! hostnames on port 443 is served, and every one is intercepted (terminated and forwarded by the
//! gateway) whether or not secrets apply, never tunnelled. Plain HTTP, raw tunnels, IP literals
//! and other ports are refused. Inside the session every request must address the CONNECT name
//! again, so a redirect to another host is a new CONNECT that the policy decides afresh. The
//! upstream is reached only through the session's validated addresses (see `dialer`).

use hyper_rustls::HttpsConnectorBuilder;
use tokio::io::{AsyncRead, AsyncWrite};

use super::*;
use crate::dialer::{DialError, Pinned};
use crate::egress::AllowedHost;

pub(super) fn refusal(code: StatusCode) -> Response<Body> {
    let mut res = text(
        code,
        "briq credential gateway: not allowed by the egress policy\n",
    );
    res.headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    res
}

/// A request inside an intercepted session: HTTP/1.1, origin-form, one Host that is exactly the
/// CONNECT name (the default port 443 may be written), no CONNECT, no upgrade.
fn check_request(req: &Request<Incoming>, host: &str) -> Result<(), StatusCode> {
    if req.method() == Method::CONNECT || req.version() != http::Version::HTTP_11 {
        return Err(StatusCode::FORBIDDEN);
    }
    let uri = req.uri();
    if uri.scheme().is_some() || uri.authority().is_some() || !uri.path().starts_with('/') {
        return Err(StatusCode::BAD_REQUEST);
    }
    if req.headers().contains_key(header::UPGRADE)
        || req.headers().get_all(header::CONNECTION).iter().any(|v| {
            v.to_str().map_or(true, |v| {
                v.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
            })
        })
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let mut hosts = req.headers().get_all(header::HOST).iter();
    let (Some(value), None) = (hosts.next(), hosts.next()) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let value = value.to_str().map_err(|_| StatusCode::BAD_REQUEST)?;
    let name = value.strip_suffix(":443").unwrap_or(value);
    if !name.eq_ignore_ascii_case(host) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(())
}

impl Gateway {
    pub(super) async fn connect_restricted(
        self: Arc<Self>,
        req: Request<Incoming>,
        peer: SocketAddr,
    ) -> Response<Body> {
        let Some(egress) = &self.egress else {
            return refusal(StatusCode::FORBIDDEN);
        };
        let uri = req.uri();
        let Some(target) = (match (uri.scheme(), uri.authority(), uri.path_and_query()) {
            (None, Some(authority), None) => Some(authority.as_str()),
            _ => None,
        }) else {
            return refusal(StatusCode::BAD_REQUEST);
        };
        let allowed = match egress.policy.authorize_connect(target) {
            Ok(allowed) => allowed,
            Err(reason) => {
                crate::log!(Warn, "egress denied", "reason": reason);
                return refusal(StatusCode::FORBIDDEN);
            }
        };
        let pinned = match egress.dialer.resolve(&allowed).await {
            Ok(pinned) => pinned,
            Err(err) => {
                crate::log!(Warn, "egress destination refused", "host": allowed.as_str(), "err": format!("{err:?}"));
                return refusal(match err {
                    DialError::NotPublic => StatusCode::FORBIDDEN,
                    _ => StatusCode::BAD_GATEWAY,
                });
            }
        };
        let briq = self.config.resolve_briq(peer.ip()).await;
        let tls = match self.leafs.for_host(allowed.as_str()) {
            Ok(cfg) => cfg,
            Err(err) => {
                crate::log!(Warn, "no certificate for the host", "host": allowed.as_str(), "err": err);
                return status(StatusCode::BAD_GATEWAY);
            }
        };
        let on_upgrade = hyper::upgrade::on(req);
        tokio::spawn(async move {
            let Ok(upgraded) = on_upgrade.await else {
                return;
            };
            let handshake = async {
                let start = tokio_rustls::LazyConfigAcceptor::new(
                    rustls::server::Acceptor::default(),
                    TokioIo::new(upgraded),
                )
                .await
                .ok()?;
                let sni = start
                    .client_hello()
                    .server_name()
                    .map(str::to_ascii_lowercase);
                if sni.as_deref() != Some(allowed.as_str()) {
                    crate::log!(Debug, "client TLS server name differs from the CONNECT host", "host": allowed.as_str());
                    return None;
                }
                start.into_stream(tls).await.ok()
            };
            let Ok(Some(stream)) =
                tokio::time::timeout(self.opts.handshake_timeout, handshake).await
            else {
                return;
            };
            self.session(stream, allowed, briq, pinned).await;
        });
        empty(StatusCode::OK)
    }

    /// Serves one intercepted connection. Its upstream pool is its own and dials only the
    /// session's validated addresses.
    async fn session<S>(
        self: Arc<Self>,
        stream: S,
        allowed: AllowedHost,
        briq: Option<String>,
        pinned: Pinned,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(self.tls.clone())
            .https_only()
            .enable_http1()
            .wrap_connector(pinned);
        let upstream = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(1)
            .http1_max_buf_size(MAX_HEADER_BYTES)
            .build(connector);
        let host: Arc<str> = allowed.as_str().into();
        let svc = service_fn(move |req| {
            let (gw, host, briq, upstream) =
                (self.clone(), host.clone(), briq.clone(), upstream.clone());
            async move {
                let res = match check_request(&req, &host) {
                    Err(code) => refusal(code),
                    Ok(()) => match gw
                        .intercept(req, &host, 443, briq.as_deref(), &upstream)
                        .await
                    {
                        Ok(res) => res,
                        Err(err) => {
                            crate::log!(Warn, "request failed", "host": host.as_ref(), "err": err.to_string());
                            status(StatusCode::BAD_GATEWAY)
                        }
                    },
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
    }
}
