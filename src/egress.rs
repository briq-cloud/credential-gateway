//! The birth egress policy: an immutable list of exact hostnames a gateway may forward to, read
//! once from `BRIQ_EGRESS_POLICY` at start. Absent, the gateway is the unrestricted one (legacy);
//! present but invalid, the gateway does not start. The one `EgressPolicy` object authorizes
//! every forward and answers the local status helper: nothing re-reads or re-parses the variable.
//!
//! ```json
//! {"policy_format":1,"namespace":"…","team_id":"…","briq_id":"…","hosts":["api.example.com"]}
//! ```
//!
//! Hosts are exact ASCII DNS names (two labels or more, no wildcard, IP, port or trailing dot),
//! lowercased, sorted and deduplicated; an empty list denies everything. The digest is SHA-256
//! of the compact JSON of that canonical form, keys in the order above.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::dialer::Dialer;

pub const POLICY_ENV: &str = "BRIQ_EGRESS_POLICY";
pub const POLICY_FORMAT: u32 = 1;
pub const ENFORCEMENT_VERSION: u32 = 1;
const MAX_POLICY_BYTES: usize = 64 * 1024;
const MAX_HOSTS: usize = 100;
const MAX_ID_BYTES: usize = 128;

/// What a restricted gateway forwards with: the policy that authorizes and the dialer that
/// reaches the authorized names.
pub struct Egress {
    pub policy: Arc<EgressPolicy>,
    pub dialer: Dialer,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Submitted {
    policy_format: u32,
    namespace: String,
    team_id: String,
    briq_id: String,
    hosts: Vec<String>,
}

/// The digested form: this field order is the contract.
#[derive(Serialize)]
struct Canonical<'a> {
    policy_format: u32,
    namespace: &'a str,
    team_id: &'a str,
    briq_id: &'a str,
    hosts: &'a [String],
}

/// What the status helper reports about the running policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Binding {
    pub policy_format: u32,
    pub policy_digest: String,
    pub enforcement_version: u32,
}

/// A policy that does not parse. It names the rule broken, never the offending content.
#[derive(Debug, PartialEq, Eq)]
pub struct PolicyError(pub &'static str);

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// A hostname the policy allows, only obtainable from `EgressPolicy::authorize_connect`. The
/// dialer takes this type, so no name is looked up before it is authorized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowedHost(String);

impl AllowedHost {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub struct EgressPolicy {
    hosts: Vec<String>,
    digest: String,
}

impl EgressPolicy {
    /// The policy in the process environment: `None` when the variable is absent (legacy),
    /// an error when it is set to anything that is not a valid policy, the empty string included.
    pub fn from_env() -> Result<Option<Self>, PolicyError> {
        match std::env::var_os(POLICY_ENV) {
            None => Ok(None),
            Some(value) => {
                let text = value
                    .to_str()
                    .ok_or(PolicyError("the policy is not valid UTF-8"))?;
                Self::parse(text).map(Some)
            }
        }
    }

    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        if text.len() > MAX_POLICY_BYTES {
            return Err(PolicyError("the policy is too large"));
        }
        let submitted: Submitted = serde_json::from_str(text)
            .map_err(|_| PolicyError("the policy is not the expected JSON"))?;
        if submitted.policy_format != POLICY_FORMAT {
            return Err(PolicyError("unsupported policy_format"));
        }
        for id in [&submitted.namespace, &submitted.team_id, &submitted.briq_id] {
            if !valid_id(id) {
                return Err(PolicyError("an identifier is empty, too long or not ASCII"));
            }
        }
        if submitted.hosts.len() > MAX_HOSTS {
            return Err(PolicyError("too many hosts"));
        }
        let mut hosts = Vec::with_capacity(submitted.hosts.len());
        for host in &submitted.hosts {
            hosts.push(canonical_host(host).ok_or(PolicyError("a host is not an exact hostname"))?);
        }
        hosts.sort();
        hosts.dedup();
        let canonical = serde_json::to_vec(&Canonical {
            policy_format: POLICY_FORMAT,
            namespace: &submitted.namespace,
            team_id: &submitted.team_id,
            briq_id: &submitted.briq_id,
            hosts: &hosts,
        })
        .map_err(|_| PolicyError("the policy cannot be digested"))?;
        let digest = ring::digest::digest(&ring::digest::SHA256, &canonical);
        let mut hex = String::from("sha256:");
        for byte in digest.as_ref() {
            hex.push_str(&format!("{byte:02x}"));
        }
        Ok(Self { hosts, digest: hex })
    }

    pub fn binding(&self) -> Binding {
        Binding {
            policy_format: POLICY_FORMAT,
            policy_digest: self.digest.clone(),
            enforcement_version: ENFORCEMENT_VERSION,
        }
    }

    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    /// The target of a CONNECT (`host:443`): allowed only when the port is exactly 443 and the
    /// host is one of the policy's, compared case-insensitively.
    pub fn authorize_connect(&self, authority: &str) -> Result<AllowedHost, &'static str> {
        let (host, port) = authority.rsplit_once(':').ok_or("the target has no port")?;
        if port != "443" {
            return Err("only port 443 is allowed");
        }
        let host = canonical_host(host).ok_or("not an exact hostname")?;
        match self.hosts.binary_search(&host) {
            Ok(_) => Ok(AllowedHost(host)),
            Err(_) => Err("host not allowed"),
        }
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_BYTES
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// The lowercase form of an exact ASCII DNS name, or `None`: two labels or more, each 1–63
/// letters, digits and inner hyphens, 253 bytes at most, and a last label that is not a number
/// (all digits, or `0x…`), which keeps IPv4 in any notation out.
pub fn canonical_host(host: &str) -> Option<String> {
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    for label in &labels {
        let bytes = label.as_bytes();
        let edge = |b: &u8| b.is_ascii_alphanumeric();
        if bytes.is_empty()
            || bytes.len() > 63
            || !bytes.first().is_some_and(edge)
            || !bytes.last().is_some_and(edge)
            || !bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return None;
        }
    }
    let last = labels[labels.len() - 1].to_ascii_lowercase();
    let numeric = last.bytes().all(|b| b.is_ascii_digit())
        || last
            .strip_prefix("0x")
            .is_some_and(|hex| !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()));
    if numeric {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(hosts: &str) -> String {
        format!(
            r#"{{"policy_format":1,"namespace":"ns-1","team_id":"team_1","briq_id":"bq_1","hosts":{hosts}}}"#
        )
    }

    #[test]
    fn canonicalizes_sorts_and_dedups() {
        let p = EgressPolicy::parse(&policy(
            r#"["B.example.com","a.example.com","b.EXAMPLE.com"]"#,
        ))
        .unwrap();
        assert_eq!(p.hosts(), ["a.example.com", "b.example.com"]);
        let same = EgressPolicy::parse(&policy(r#"["a.example.com","b.example.com"]"#)).unwrap();
        assert_eq!(p.binding(), same.binding());
    }

    #[test]
    fn digest_is_sha256_of_the_compact_canonical_json() {
        let p = EgressPolicy::parse(&policy(r#"["a.example.com"]"#)).unwrap();
        let canonical = r#"{"policy_format":1,"namespace":"ns-1","team_id":"team_1","briq_id":"bq_1","hosts":["a.example.com"]}"#;
        let digest = ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes());
        let want: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        let b = p.binding();
        assert_eq!(b.policy_digest, format!("sha256:{want}"));
        assert_eq!((b.policy_format, b.enforcement_version), (1, 1));
        let other = EgressPolicy::parse(&policy(r#"["a.example.org"]"#)).unwrap();
        assert_ne!(other.binding().policy_digest, b.policy_digest);
    }

    #[test]
    fn matches_the_cross_language_vector() {
        let p = EgressPolicy::parse(
            r#"{"policy_format":1,"namespace":"bqt-team-tm_1--bq_1","team_id":"tm_1","briq_id":"bq_1","hosts":["example.com","API.example.com"]}"#,
        )
        .unwrap();
        assert_eq!(
            p.binding().policy_digest,
            "sha256:8eb7022fc36c3c2836b9fac27eb459b57e7141268acc58cf3437989ef737cb7b"
        );
    }

    #[test]
    fn empty_policy_denies_everything() {
        let p = EgressPolicy::parse(&policy("[]")).unwrap();
        assert!(p.hosts().is_empty());
        assert!(p.authorize_connect("a.example.com:443").is_err());
    }

    #[test]
    fn rejects_malformed_policies_without_echoing_them() {
        let bad = [
            String::new(),
            "null".into(),
            "{}".into(),
            policy(r#"["*.example.com"]"#),
            policy(r#"["example"]"#),
            policy(r#"["1.2.3.4"]"#),
            policy(r#"["0x7f.0x1"]"#),
            policy(r#"["127.1"]"#),
            policy(r#"["example.com."]"#),
            policy(r#"["example.com:443"]"#),
            policy(r#"["https://example.com"]"#),
            policy(r#"[" example.com"]"#),
            policy(r#"["exa mple.com"]"#),
            policy(r#"["-a.example.com"]"#),
            policy(r#"["a-.example.com"]"#),
            policy(r#"["a..example.com"]"#),
            policy(r#"["bücher.example.com"]"#),
            policy(r#"[1]"#),
            policy(r#"null"#),
            policy(&format!(r#"["{}.example.com"]"#, "a".repeat(64))),
            policy(&format!("[{}]", vec![r#""a.example.com""#; 101].join(","))),
            r#"{"policy_format":2,"namespace":"n","team_id":"t","briq_id":"b","hosts":[]}"#.into(),
            r#"{"policy_format":"1","namespace":"n","team_id":"t","briq_id":"b","hosts":[]}"#.into(),
            r#"{"policy_format":1,"namespace":"","team_id":"t","briq_id":"b","hosts":[]}"#.into(),
            r#"{"policy_format":1,"namespace":"n n","team_id":"t","briq_id":"b","hosts":[]}"#.into(),
            r#"{"policy_format":1,"namespace":"n.n","team_id":"t","briq_id":"b","hosts":[]}"#.into(),
            r#"{"policy_format":1,"namespace":"n:n","team_id":"t","briq_id":"b","hosts":[]}"#.into(),
            r#"{"policy_format":1,"namespace":"é","team_id":"t","briq_id":"b","hosts":[]}"#.into(),
            r#"{"policy_format":1,"namespace":"n","team_id":"t","hosts":[]}"#.into(),
            r#"{"policy_format":1,"namespace":"n","team_id":"t","briq_id":"b","hosts":[],"extra":1}"#
                .into(),
            r#"{"policy_format":1,"policy_format":1,"namespace":"n","team_id":"t","briq_id":"b","hosts":[]}"#
                .into(),
            r#"{"policy_format":1,"namespace":"n","team_id":"t","briq_id":"b","hosts":[]} x"#.into(),
            format!(
                r#"{{"policy_format":1,"namespace":"{}","team_id":"t","briq_id":"b","hosts":[]}}"#,
                "n".repeat(129)
            ),
            " ".repeat(MAX_POLICY_BYTES + 1),
        ];
        for text in bad {
            let err = EgressPolicy::parse(&text).err().unwrap_or_else(|| {
                panic!("accepted {}", text.chars().take(80).collect::<String>())
            });
            assert!(!err.to_string().contains("example"), "{err}");
        }
        let hundred = format!("[{}]", vec![r#""a.example.com""#; 100].join(","));
        assert!(EgressPolicy::parse(&policy(&hundred)).is_ok());
    }

    #[test]
    fn authorizes_only_exact_names_on_port_443() {
        let p = EgressPolicy::parse(&policy(r#"["api.example.com"]"#)).unwrap();
        assert_eq!(
            p.authorize_connect("API.Example.COM:443").unwrap().as_str(),
            "api.example.com"
        );
        for denied in [
            "api.example.com:80",
            "api.example.com:8443",
            "api.example.com:0443",
            "api.example.com:+443",
            "api.example.com",
            "api.example.com.:443",
            "x.api.example.com:443",
            "example.com:443",
            "*.example.com:443",
            "1.2.3.4:443",
            "[::1]:443",
            "::1:443",
            "user@api.example.com:443",
            "api.example.com:443:443",
            " api.example.com:443",
            "api.example.com :443",
            "",
            ":443",
        ] {
            assert!(p.authorize_connect(denied).is_err(), "{denied}");
        }
    }

    #[test]
    fn environment_absent_is_legacy_and_present_must_parse() {
        // Env mutation is process-wide: only this test touches the variable.
        unsafe { std::env::remove_var(POLICY_ENV) };
        assert!(EgressPolicy::from_env().unwrap().is_none());
        unsafe { std::env::set_var(POLICY_ENV, "") };
        assert!(EgressPolicy::from_env().is_err());
        unsafe { std::env::set_var(POLICY_ENV, "{") };
        assert!(EgressPolicy::from_env().is_err());
        unsafe { std::env::set_var(POLICY_ENV, policy("[]")) };
        assert!(EgressPolicy::from_env().unwrap().is_some());
        unsafe { std::env::remove_var(POLICY_ENV) };
    }
}
