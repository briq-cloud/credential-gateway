//! The local policy status: what a restricted gateway answers when the machine's tooling asks
//! which policy it is enforcing, over a Unix socket only root can reach (no network endpoint).
//!
//! `credential-gateway policy-status <challenge>` takes 64 lowercase hex characters, sends them to
//! the running gateway at `/run/credential-gateway/policy.sock` and prints one JSON object:
//!
//! ```json
//! {"challenge":"…","policy_format":1,"policy_digest":"sha256:…","enforcement_version":1,"ready":true}
//! ```
//!
//! The answer is built from the `EgressPolicy` that authorizes forwarding, by a server that only
//! exists after the proxy listener is bound; nothing is read from the environment or a file. A
//! gateway without a policy runs no status server, so the helper fails for it. Any failure exits
//! non-zero with a fixed message: no policy content, peer data or error detail is printed.

use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::egress::{ENFORCEMENT_VERSION, EgressPolicy, POLICY_FORMAT};

pub const SOCKET_DIR: &str = "/run/credential-gateway";
pub const SOCKET_PATH: &str = "/run/credential-gateway/policy.sock";
const CHALLENGE_BYTES: usize = 64;
const MAX_RESPONSE_BYTES: usize = 4096;
const EXCHANGE: Duration = Duration::from_secs(2);
const MAX_CLIENTS: usize = 8;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Answer {
    challenge: String,
    policy_format: u32,
    policy_digest: String,
    enforcement_version: u32,
    ready: bool,
}

fn valid_challenge(text: &str) -> bool {
    text.len() == CHALLENGE_BYTES && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn valid_digest(text: &str) -> bool {
    text.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// The helper: asks the gateway and returns the validated answer as one line of JSON.
pub async fn ask(challenge: &str) -> Option<String> {
    ask_at(Path::new(SOCKET_PATH), challenge, EXCHANGE).await
}

async fn ask_at(path: &Path, challenge: &str, deadline: Duration) -> Option<String> {
    if !valid_challenge(challenge) {
        return None;
    }
    let exchange = async {
        let mut stream = UnixStream::connect(path).await.ok()?;
        stream
            .write_all(format!("{challenge}\n").as_bytes())
            .await
            .ok()?;
        let mut reply = Vec::new();
        (&mut stream)
            .take(MAX_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut reply)
            .await
            .ok()?;
        Some(reply)
    };
    let reply = timeout(deadline, exchange).await.ok()??;
    if reply.len() > MAX_RESPONSE_BYTES {
        return None;
    }
    let answer: Answer = serde_json::from_slice(&reply).ok()?;
    let sound = answer.challenge == challenge
        && answer.policy_format == POLICY_FORMAT
        && answer.enforcement_version == ENFORCEMENT_VERSION
        && answer.ready
        && valid_digest(&answer.policy_digest);
    sound.then(|| serde_json::to_string(&answer).ok()).flatten()
}

/// The bound status socket. Dropping it removes the socket if it is still the one it made.
pub struct StatusSocket {
    listener: UnixListener,
    path: PathBuf,
    identity: (u64, u64),
}

impl StatusSocket {
    /// Binds the fixed socket: its directory root-only (0700), the socket 0600.
    pub fn bind() -> io::Result<Self> {
        Self::bind_at(Path::new(SOCKET_DIR), Path::new(SOCKET_PATH))
    }

    fn bind_at(dir: &Path, path: &Path) -> io::Result<Self> {
        let me = unsafe { libc::geteuid() };
        match fs::symlink_metadata(dir) {
            Ok(meta) if !meta.is_dir() => {
                return Err(io::Error::other("status directory is not a directory"));
            }
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => fs::create_dir_all(dir)?,
            Err(err) => return Err(err),
        }
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        let meta = fs::symlink_metadata(dir)?;
        if !meta.is_dir() || meta.uid() != me || meta.mode() & 0o077 != 0 {
            return Err(io::Error::other("status directory is not private"));
        }
        match fs::symlink_metadata(path) {
            Ok(old) if old.file_type().is_socket() && old.uid() == me => {
                // A socket something still answers on belongs to a running gateway.
                if std::os::unix::net::UnixStream::connect(path).is_ok() {
                    return Err(io::Error::other("another gateway holds the status socket"));
                }
                fs::remove_file(path)?;
            }
            Ok(_) => {
                return Err(io::Error::other(
                    "something else is at the status socket path",
                ));
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        let made = fs::symlink_metadata(path)?;
        Ok(Self {
            listener,
            path: path.to_path_buf(),
            identity: (made.dev(), made.ino()),
        })
    }

    /// Answers challenges from the policy until the task is dropped.
    pub async fn serve(&self, policy: Arc<EgressPolicy>) {
        let clients = Arc::new(Semaphore::new(MAX_CLIENTS));
        let me = unsafe { libc::geteuid() };
        loop {
            let Ok((stream, _)) = self.listener.accept().await else {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            };
            let Ok(permit) = clients.clone().try_acquire_owned() else {
                continue;
            };
            if stream.peer_cred().map(|c| c.uid()).ok() != Some(me) {
                continue;
            }
            let policy = policy.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ = timeout(EXCHANGE, answer(stream, &policy)).await;
            });
        }
    }
}

impl Drop for StatusSocket {
    fn drop(&mut self) {
        if let Ok(meta) = fs::symlink_metadata(&self.path)
            && (meta.dev(), meta.ino()) == self.identity
            && meta.file_type().is_socket()
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

async fn answer(mut stream: UnixStream, policy: &EgressPolicy) -> Option<()> {
    let mut line = Vec::new();
    BufReader::new((&mut stream).take(CHALLENGE_BYTES as u64 + 1))
        .read_until(b'\n', &mut line)
        .await
        .ok()?;
    let challenge = std::str::from_utf8(&line).ok()?.strip_suffix('\n')?;
    if !valid_challenge(challenge) {
        return None;
    }
    let binding = policy.binding();
    let body = serde_json::to_vec(&Answer {
        challenge: challenge.to_string(),
        policy_format: binding.policy_format,
        policy_digest: binding.policy_digest,
        enforcement_version: binding.enforcement_version,
        ready: true,
    })
    .ok()?;
    stream.write_all(&body).await.ok()?;
    stream.shutdown().await.ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHALLENGE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn policy() -> Arc<EgressPolicy> {
        Arc::new(
            EgressPolicy::parse(
                r#"{"policy_format":1,"namespace":"n","team_id":"t","briq_id":"b","hosts":["a.example.com"]}"#,
            )
            .unwrap(),
        )
    }

    fn paths(root: &Path) -> (PathBuf, PathBuf) {
        let dir = root.join("run");
        let path = dir.join("policy.sock");
        (dir, path)
    }

    async fn running(root: &Path) -> (PathBuf, Arc<EgressPolicy>, tokio::task::JoinHandle<()>) {
        let (dir, path) = paths(root);
        let policy = policy();
        let socket = StatusSocket::bind_at(&dir, &path).unwrap();
        let p = policy.clone();
        let task = tokio::spawn(async move { socket.serve(p).await });
        (path, policy, task)
    }

    #[tokio::test]
    async fn answers_a_challenge_from_the_enforcing_policy() {
        let root = tempfile::tempdir().unwrap();
        let (path, policy, _task) = running(root.path()).await;
        let out = ask_at(&path, CHALLENGE, Duration::from_secs(2))
            .await
            .unwrap();
        let b = policy.binding();
        assert_eq!(
            out,
            format!(
                r#"{{"challenge":"{CHALLENGE}","policy_format":1,"policy_digest":"{}","enforcement_version":1,"ready":true}}"#,
                b.policy_digest
            )
        );
        assert!(!out.contains('\n'));
        let other = "f".repeat(64);
        assert!(
            ask_at(&path, &other, Duration::from_secs(2))
                .await
                .unwrap()
                .contains(&other)
        );
    }

    #[tokio::test]
    async fn refuses_malformed_challenges_on_both_sides() {
        let root = tempfile::tempdir().unwrap();
        let (path, _policy, _task) = running(root.path()).await;
        for bad in [
            "",
            "abc",
            &CHALLENGE.to_uppercase(),
            &format!("{CHALLENGE}0"),
            &CHALLENGE[1..],
            &format!("{}g", &CHALLENGE[1..]),
        ] {
            assert!(
                ask_at(&path, bad, Duration::from_secs(1)).await.is_none(),
                "{bad}"
            );
        }
        for raw in [
            &b"short\n"[..],
            &b"not hex not hex not hex not hex not hex not hex not hex not hex!\n"[..],
            &[b'a'; 200][..],
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ] {
            let mut s = UnixStream::connect(&path).await.unwrap();
            let _ = s.write_all(raw).await;
            let _ = s.shutdown().await;
            let mut reply = Vec::new();
            let _ = timeout(Duration::from_secs(3), s.read_to_end(&mut reply)).await;
            assert!(reply.is_empty());
        }
    }

    #[tokio::test]
    async fn a_silent_client_is_dropped_by_the_deadline() {
        let root = tempfile::tempdir().unwrap();
        let (path, _policy, _task) = running(root.path()).await;
        let mut s = UnixStream::connect(&path).await.unwrap();
        let mut reply = Vec::new();
        let read = timeout(Duration::from_secs(4), s.read_to_end(&mut reply)).await;
        assert!(read.is_ok() && reply.is_empty());
    }

    async fn fake(root: &Path, reply: Vec<u8>, stall: bool) -> PathBuf {
        let (dir, path) = paths(root);
        let socket = StatusSocket::bind_at(&dir, &path).unwrap();
        tokio::spawn(async move {
            let _keep = &socket;
            loop {
                let (mut s, _) = socket.listener.accept().await.unwrap();
                let reply = reply.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 65];
                    let _ = s.read(&mut buf).await;
                    if stall {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                    let _ = s.write_all(&reply).await;
                });
            }
        });
        path
    }

    fn good(challenge: &str) -> serde_json::Value {
        serde_json::json!({
            "challenge": challenge,
            "policy_format": 1,
            "policy_digest": format!("sha256:{}", "a".repeat(64)),
            "enforcement_version": 1,
            "ready": true,
        })
    }

    #[tokio::test]
    async fn the_helper_rejects_every_unsound_answer() {
        let mut cases: Vec<Vec<u8>> = Vec::new();
        let mutate = |f: &dyn Fn(&mut serde_json::Value)| {
            let mut v = good(CHALLENGE);
            f(&mut v);
            v.to_string().into_bytes()
        };
        cases.push(mutate(&|v| v["challenge"] = "f".repeat(64).into()));
        cases.push(mutate(&|v| v["ready"] = false.into()));
        cases.push(mutate(&|v| v["policy_format"] = 2.into()));
        cases.push(mutate(&|v| v["enforcement_version"] = 2.into()));
        cases.push(mutate(&|v| v["policy_digest"] = "sha256:ABC".into()));
        cases.push(mutate(&|v| {
            v["policy_digest"] = format!("sha1:{}", "a".repeat(64)).into()
        }));
        cases.push(mutate(&|v| v["extra"] = 1.into()));
        cases.push(mutate(&|v| {
            v.as_object_mut().unwrap().remove("ready");
        }));
        cases.push(b"not json".to_vec());
        cases.push(Vec::new());
        let mut two = good(CHALLENGE).to_string();
        two.push_str(&good(CHALLENGE).to_string());
        cases.push(two.into_bytes());
        let mut padded = good(CHALLENGE).to_string().into_bytes();
        padded.resize(MAX_RESPONSE_BYTES + 1, b' ');
        cases.push(padded);
        for reply in cases {
            let root = tempfile::tempdir().unwrap();
            let path = fake(root.path(), reply.clone(), false).await;
            let got = ask_at(&path, CHALLENGE, Duration::from_secs(2)).await;
            assert!(
                got.is_none(),
                "{}",
                String::from_utf8_lossy(&reply[..reply.len().min(100)])
            );
        }
        let root = tempfile::tempdir().unwrap();
        let path = fake(root.path(), good(CHALLENGE).to_string().into_bytes(), false).await;
        assert!(
            ask_at(&path, CHALLENGE, Duration::from_secs(2))
                .await
                .is_some()
        );
        let mut limit = good(CHALLENGE).to_string().into_bytes();
        limit.resize(MAX_RESPONSE_BYTES, b' ');
        let root = tempfile::tempdir().unwrap();
        let path = fake(root.path(), limit, false).await;
        assert!(
            ask_at(&path, CHALLENGE, Duration::from_secs(2))
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn the_helper_gives_up_on_a_stalled_gateway_and_a_missing_socket() {
        let root = tempfile::tempdir().unwrap();
        let path = fake(root.path(), Vec::new(), true).await;
        let started = std::time::Instant::now();
        assert!(
            ask_at(&path, CHALLENGE, Duration::from_millis(300))
                .await
                .is_none()
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        let missing = root.path().join("nope.sock");
        assert!(
            ask_at(&missing, CHALLENGE, Duration::from_secs(1))
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn socket_is_private_replaces_a_stale_one_and_is_removed_on_drop() {
        let root = tempfile::tempdir().unwrap();
        let (dir, path) = paths(root.path());
        let socket = StatusSocket::bind_at(&dir, &path).unwrap();
        let mode = |p: &Path| fs::symlink_metadata(p).unwrap().mode() & 0o777;
        assert_eq!((mode(&dir), mode(&path)), (0o700, 0o600));
        assert!(
            StatusSocket::bind_at(&dir, &path).is_err(),
            "a live socket is not taken over"
        );
        drop(socket);
        assert!(!path.exists());
        let stale = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(stale);
        assert!(
            path.exists(),
            "a dead gateway leaves its socket file behind"
        );
        let socket = StatusSocket::bind_at(&dir, &path).unwrap();
        drop(socket);
        assert!(!path.exists());
        fs::write(&path, b"not a socket").unwrap();
        assert!(StatusSocket::bind_at(&dir, &path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"not a socket");
        fs::remove_file(&path).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let again = StatusSocket::bind_at(&dir, &path).unwrap();
        assert_eq!(mode(&dir), 0o700);
        let replaced = path.with_extension("moved");
        fs::rename(&path, &replaced).unwrap();
        let ours = again.identity;
        drop(again);
        assert!(replaced.exists(), "only the socket it made is removed");
        assert_eq!(ours.1, fs::symlink_metadata(&replaced).unwrap().ino());
    }

    #[tokio::test]
    async fn a_symlinked_or_foreign_directory_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(StatusSocket::bind_at(&link, &link.join("policy.sock")).is_err());
        let file = root.path().join("file");
        fs::write(&file, b"").unwrap();
        assert!(StatusSocket::bind_at(&file, &file.join("policy.sock")).is_err());
    }
}
