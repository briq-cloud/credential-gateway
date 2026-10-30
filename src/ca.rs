//! The gateway's certificate authority: one per team, made on first boot and kept on the gateway's
//! own disk. Its key never leaves the machine; the API gets the certificate, which it hands to the
//! team's briqs. Leaf certificates for the hosts the gateway terminates TLS for are made from it
//! on demand and cached.
//!
//! A CA that is there but cannot be read stops the gateway instead of being replaced: the team's
//! briqs trust the one they were given, and a new one would break every one of them.

use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SerialNumber,
};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration, OffsetDateTime};

const CERT_FILE: &str = "ca.crt";
const KEY_FILE: &str = "ca.key";
/// Leaf certificates kept; past it, the expired ones go, then all of them (a wildcard host
/// pattern lets a client ask for any number of names).
const MAX_LEAFS: usize = 1024;

pub struct Ca {
    /// The certificate, PEM: what the API is told and the briqs trust.
    pub cert_pem: String,
    pub subject: String,
    cert_der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

impl Ca {
    /// The CA in `dir`, or a new one when there is none. `name` is what a new one says it is for.
    pub fn load_or_create(dir: &Path, name: &str) -> Result<Ca, String> {
        let cert_path = dir.join(CERT_FILE);
        let key_path = dir.join(KEY_FILE);
        let cert = read_if_there(&cert_path)?;
        let key = read_if_there(&key_path)?;
        match (cert, key) {
            (Some(cert), Some(key)) => Self::load(&cert, &key),
            (None, None) => Self::create(dir, name),
            _ => Err(format!(
                "{} has one of {CERT_FILE} and {KEY_FILE} without the other",
                dir.display()
            )),
        }
    }

    /// The certificate, DER.
    pub fn cert_der(&self) -> CertificateDer<'static> {
        self.cert_der.clone()
    }

    fn load(cert_pem: &str, key_pem: &str) -> Result<Ca, String> {
        let key = KeyPair::from_pem(key_pem).map_err(|e| format!("{KEY_FILE}: {e}"))?;
        let der = pem_der(cert_pem).ok_or_else(|| format!("{CERT_FILE}: not a PEM certificate"))?;
        let subject = subject_of(&der)?;
        let issuer =
            Issuer::from_ca_cert_der(&der, key).map_err(|e| format!("{CERT_FILE}: {e}"))?;
        Ok(Ca {
            cert_pem: cert_pem.to_string(),
            subject,
            cert_der: der,
            issuer,
        })
    }

    fn create(dir: &Path, name: &str) -> Result<Ca, String> {
        fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
        let now = OffsetDateTime::now_utc();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, format!("briq gateway ({name})"));
        params
            .distinguished_name
            .push(DnType::OrganizationName, "briq");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(3650);
        params.serial_number = Some(serial());
        let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
        let cert_pem = cert.pem();
        write_private(&dir.join(KEY_FILE), &key.serialize_pem())?;
        fs::write(dir.join(CERT_FILE), &cert_pem).map_err(|e| format!("{CERT_FILE}: {e}"))?;
        let der = cert.der().clone();
        let subject = subject_of(&der)?;
        Ok(Ca {
            cert_pem,
            subject,
            cert_der: der,
            issuer: Issuer::new(params, key),
        })
    }
}

/// Leaf certificates by host, made from the CA, all on one key pair, as TLS server configs.
pub struct Leafs {
    ca: Ca,
    key: KeyPair,
    cache: Mutex<HashMap<String, (Arc<ServerConfig>, OffsetDateTime)>>,
}

impl Leafs {
    pub fn new(ca: Ca) -> Result<Self, String> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
        Ok(Self {
            ca,
            key,
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn ca(&self) -> &Ca {
        &self.ca
    }

    /// The server config for `host`, made again when it has less than a day left.
    pub fn for_host(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        let now = OffsetDateTime::now_utc();
        if let Some((cfg, expires)) = self.cache.lock().unwrap().get(host)
            && *expires > now + Duration::days(1)
        {
            return Ok(cfg.clone());
        }
        let not_after = now + Duration::days(30);
        let mut params =
            CertificateParams::new(vec![host.to_string()]).map_err(|e| e.to_string())?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.not_before = now - Duration::days(1);
        params.not_after = not_after;
        params.serial_number = Some(serial());
        let cert = params
            .signed_by(&self.key, &self.ca.issuer)
            .map_err(|e| e.to_string())?;
        let chain = vec![cert.der().clone(), self.ca.cert_der.clone()];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.serialize_der()));
        let mut cfg =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|e| e.to_string())?
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .map_err(|e| e.to_string())?;
        // HTTP/1.1 only: clients that offer h2 fall back.
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        let mut cache = self.cache.lock().unwrap();
        if cache.len() >= MAX_LEAFS {
            cache.retain(|_, (_, expires)| *expires > now + Duration::days(1));
            if cache.len() >= MAX_LEAFS {
                cache.clear();
            }
        }
        cache.insert(host.to_string(), (cfg.clone(), not_after));
        Ok(cfg)
    }
}

fn read_if_there(path: &Path) -> Result<Option<String>, String> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn write_private(path: &Path, text: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        f.write_all(text.as_bytes())
            .map_err(|e| format!("{}: {e}", path.display()))
    }
    #[cfg(not(unix))]
    fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

fn pem_der(text: &str) -> Option<CertificateDer<'static>> {
    let p = pem::parse(text).ok()?;
    (p.tag() == "CERTIFICATE").then(|| CertificateDer::from(p.into_contents()))
}

fn subject_of(der: &CertificateDer<'_>) -> Result<String, String> {
    let (_, x) =
        x509_parser::parse_x509_certificate(der).map_err(|e| format!("{CERT_FILE}: {e}"))?;
    Ok(x.subject().to_string())
}

/// 12 random bytes, positive.
fn serial() -> SerialNumber {
    let mut b: [u8; 12] = rand::random();
    b[0] &= 0x7f;
    SerialNumber::from_slice(&b)
}
