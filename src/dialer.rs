//! How a restricted gateway reaches an authorized name: resolve it once, refuse the whole
//! answer if any address is not public, and from then on dial only those literal addresses. A
//! `Pinned` connector belongs to one CONNECT session: when the session's pool opens another
//! socket, it uses the same validated literals and never asks DNS again, so a name that changes
//! its answer after validation (rebinding) is not followed.
//!
//! Public means global unicast, conservatively. IPv4 refused: 0.0.0.0/8, 10/8, 100.64/10,
//! 127/8, 169.254/16, 172.16/12, 192.0.0/24, 192.0.2/24, 192.88.99/24, 192.168/16, 198.18/15,
//! 198.51.100/24, 203.0.113/24, 224/4 (multicast) and 240/4 (reserved, broadcast). IPv6 accepted
//! only inside 2000::/3 and outside 2001::/23 (protocol assignments, Teredo), 2001:db8::/32,
//! 2002::/16 (6to4) and 3fff::/20 (documentation); so loopback, unspecified, IPv4-mapped and
//! -compatible, NAT64/translation, ULA, link-local, site-local and multicast are all refused.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http::Uri;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tower_service::Service;

use crate::config::{Resolve, dns};
use crate::egress::AllowedHost;

const HTTPS_PORT: u16 = 443;
const MAX_ADDRESSES: usize = 8;

/// Opens a TCP connection to an already validated address: the real network, or a test's
/// stand-in. It is only ever handed addresses that passed `is_public`.
pub type Connect = Arc<
    dyn Fn(SocketAddr) -> Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>> + Send + Sync,
>;

#[derive(Debug, PartialEq, Eq)]
pub enum DialError {
    /// The lookup failed or ran past its deadline.
    Lookup,
    /// The lookup answered with no address.
    NoAddress,
    /// At least one address is not public.
    NotPublic,
}

pub struct Dialer {
    resolve: Resolve,
    connect: Connect,
    lookup_deadline: Duration,
}

impl Dialer {
    /// The system resolver and real sockets.
    pub fn system() -> Self {
        Self::new(
            dns(),
            Arc::new(|addr| Box::pin(async move { TcpStream::connect(addr).await })),
        )
    }

    /// A resolver and transport of the caller's. Classification still applies to every address
    /// before the transport sees it.
    pub fn new(resolve: Resolve, connect: Connect) -> Self {
        Self {
            resolve,
            connect,
            lookup_deadline: Duration::from_secs(5),
        }
    }

    pub fn with_lookup_deadline(mut self, deadline: Duration) -> Self {
        self.lookup_deadline = deadline;
        self
    }

    /// One lookup of an authorized name. Every address must be public; the connector returned
    /// dials those addresses, port 443, and nothing else.
    pub async fn resolve(&self, host: &AllowedHost) -> Result<Pinned, DialError> {
        let answer = timeout(
            self.lookup_deadline,
            (self.resolve)(host.as_str().to_string()),
        )
        .await
        .map_err(|_| DialError::Lookup)?
        .map_err(|_| DialError::Lookup)?;
        if answer.is_empty() {
            return Err(DialError::NoAddress);
        }
        let mut addrs: Vec<SocketAddr> = Vec::new();
        for ip in answer {
            if !is_public(ip) {
                return Err(DialError::NotPublic);
            }
            let addr = SocketAddr::new(ip, HTTPS_PORT);
            if !addrs.contains(&addr) {
                addrs.push(addr);
            }
        }
        addrs.truncate(MAX_ADDRESSES);
        Ok(Pinned {
            host: host.as_str().into(),
            addrs: addrs.into(),
            connect: self.connect.clone(),
        })
    }
}

/// Dials the validated addresses of one authorized name, whatever the URI's port says, and only
/// for that name.
#[derive(Clone)]
pub struct Pinned {
    host: Arc<str>,
    addrs: Arc<[SocketAddr]>,
    connect: Connect,
}

impl Pinned {
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addrs
    }
}

impl Service<Uri> for Pinned {
    type Response = TokioIo<TcpStream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<TokioIo<TcpStream>>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let me = self.clone();
        Box::pin(async move {
            if uri.host() != Some(&*me.host) {
                return Err(io::Error::other("not the authorized host"));
            }
            let attempts = async {
                let mut last = io::Error::other("no address");
                for addr in me.addrs.iter() {
                    match timeout(Duration::from_secs(5), (me.connect)(*addr)).await {
                        Ok(Ok(stream)) => {
                            let _ = stream.set_nodelay(true);
                            return Ok(TokioIo::new(stream));
                        }
                        Ok(Err(err)) => last = err,
                        Err(_) => {
                            last = io::Error::new(io::ErrorKind::TimedOut, "connect timed out")
                        }
                    }
                }
                Err(last)
            };
            timeout(Duration::from_secs(10), attempts)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))?
        })
    }
}

/// Whether an address may be dialed: see the module's list.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => public_v4(ip),
        IpAddr::V6(ip) => public_v6(ip),
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || (a == 100 && (64..=127).contains(&b))
        || a == 127
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    (s[0] & 0xe000) == 0x2000
        && !(s[0] == 0x2001 && s[1] < 0x0200)
        && !(s[0] == 0x2001 && s[1] == 0x0db8)
        && s[0] != 0x2002
        && !(s[0] == 0x3fff && s[1] < 0x1000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::EgressPolicy;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn allowed(host: &str) -> AllowedHost {
        let policy = EgressPolicy::parse(&format!(
            r#"{{"policy_format":1,"namespace":"n","team_id":"t","briq_id":"b","hosts":["{host}"]}}"#
        ))
        .unwrap();
        policy.authorize_connect(&format!("{host}:443")).unwrap()
    }

    fn answering(ips: &[&str], lookups: Arc<AtomicUsize>) -> Resolve {
        let ips: Vec<IpAddr> = ips.iter().map(|ip| ip.parse().unwrap()).collect();
        Arc::new(move |_| {
            lookups.fetch_add(1, Ordering::SeqCst);
            let ips = ips.clone();
            Box::pin(async move { Ok(ips) })
        })
    }

    fn never_connect() -> Connect {
        Arc::new(|_| Box::pin(async { Err(io::Error::other("no transport")) }))
    }

    #[test]
    fn classifies_addresses() {
        for public in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "100.63.255.255",
            "100.128.0.1",
            "172.15.0.1",
            "172.32.0.1",
            "192.0.1.1",
            "192.169.0.1",
            "198.17.0.1",
            "198.20.0.1",
            "223.255.255.255",
            "2606:4700:4700::1111",
            "2a00:1450:4007::200e",
            "2001:200::1",
            "2001:4860:4860::8888",
        ] {
            assert!(is_public(public.parse().unwrap()), "{public}");
        }
        for private in [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "127.255.255.254",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:8.8.8.8",
            "::ffff:127.0.0.1",
            "::8.8.8.8",
            "64:ff9b::808:808",
            "64:ff9b:1::1",
            "100::1",
            "2001::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "2001:1ff::1",
            "2001:db8::1",
            "2002:808:808::1",
            "3fff::1",
            "3fff:fff::1",
            "5f00::1",
            "fc00::1",
            "fd00::1",
            "fdaa::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "4000::1",
        ] {
            assert!(!is_public(private.parse().unwrap()), "{private}");
        }
    }

    #[tokio::test]
    async fn resolves_once_and_pins_validated_literals() {
        let lookups = Arc::new(AtomicUsize::new(0));
        let dialer = Dialer::new(
            answering(
                &["93.184.216.34", "2606:2800:220:1::1", "93.184.216.34"],
                lookups.clone(),
            ),
            never_connect(),
        );
        let pinned = dialer.resolve(&allowed("api.example.com")).await.unwrap();
        assert_eq!(
            pinned.addresses(),
            [
                "93.184.216.34:443".parse::<SocketAddr>().unwrap(),
                "[2606:2800:220:1::1]:443".parse().unwrap()
            ]
        );
        assert_eq!(lookups.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn refuses_the_whole_answer_when_any_address_is_not_public() {
        for ips in [
            vec!["93.184.216.34", "10.0.0.5"],
            vec!["127.0.0.1"],
            vec!["::ffff:93.184.216.34"],
            vec!["2606:2800:220:1::1", "fd00::1"],
        ] {
            let dialer = Dialer::new(answering(&ips, Arc::default()), never_connect());
            assert_eq!(
                dialer.resolve(&allowed("api.example.com")).await.err(),
                Some(DialError::NotPublic),
                "{ips:?}"
            );
        }
    }

    #[tokio::test]
    async fn refuses_empty_failed_and_slow_lookups() {
        let dialer = Dialer::new(answering(&[], Arc::default()), never_connect());
        assert_eq!(
            dialer.resolve(&allowed("api.example.com")).await.err(),
            Some(DialError::NoAddress)
        );
        let failing: Resolve = Arc::new(|_| Box::pin(async { Err(io::Error::other("nxdomain")) }));
        let dialer = Dialer::new(failing, never_connect());
        assert_eq!(
            dialer.resolve(&allowed("api.example.com")).await.err(),
            Some(DialError::Lookup)
        );
        let slow: Resolve = Arc::new(|_| {
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Ok(vec!["93.184.216.34".parse().unwrap()])
            })
        });
        let dialer =
            Dialer::new(slow, never_connect()).with_lookup_deadline(Duration::from_millis(50));
        assert_eq!(
            dialer.resolve(&allowed("api.example.com")).await.err(),
            Some(DialError::Lookup)
        );
    }

    #[tokio::test]
    async fn reconnects_use_the_validated_literals_not_a_new_lookup() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        let tried = Arc::new(Mutex::new(Vec::new()));
        let seen = tried.clone();
        let connect: Connect = Arc::new(move |addr| {
            seen.lock().unwrap().push(addr);
            Box::pin(async move {
                if addr.is_ipv6() {
                    return Err(io::Error::other("unreachable"));
                }
                TcpStream::connect(local).await
            })
        });
        let lookups = Arc::new(AtomicUsize::new(0));
        let dialer = Dialer::new(
            answering(&["2606:2800:220:1::1", "93.184.216.34"], lookups.clone()),
            connect,
        );
        let mut pinned = dialer.resolve(&allowed("api.example.com")).await.unwrap();
        for _ in 0..3 {
            pinned
                .call("https://api.example.com:443/".parse().unwrap())
                .await
                .unwrap();
        }
        assert_eq!(lookups.load(Ordering::SeqCst), 1);
        let attempts = tried.lock().unwrap().clone();
        assert_eq!(attempts.len(), 6);
        assert!(
            attempts
                .iter()
                .all(|a| a.port() == 443 && is_public(a.ip()))
        );
        assert!(
            pinned
                .call("https://other.example.com/".parse().unwrap())
                .await
                .is_err()
        );
        assert_eq!(tried.lock().unwrap().len(), 6);
    }
}
