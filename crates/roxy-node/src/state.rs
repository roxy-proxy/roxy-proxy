//! The state dir: the node certificate and key, the flow sequence counter
//! and the interception CA's directory. Nothing else is ever written here;
//! secrets and the rendered config stay in memory.

use std::io;
use std::path::{Path, PathBuf};

/// The node certificate chain, PEM.
pub const CERT_FILE: &str = "node.crt";
/// The node's PKCS#8 key, PEM, mode 0600.
pub const KEY_FILE: &str = "node.key";
/// The flow `seq` counter: the highest value reserved so far.
pub const SEQ_FILE: &str = "flow.seq";
/// Where the interception CA lives (`tls.ca_dir`).
pub const CA_DIR: &str = "ca";

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("state dir {} has {present} but not {missing}; remove it to enrol again", dir.display())]
    Incomplete {
        dir: PathBuf,
        present: &'static str,
        missing: &'static str,
    },
    #[error("{}: not a flow sequence number: {text:?}", path.display())]
    BadSeq { path: PathBuf, text: String },
}

/// A certificate and key read from the state dir.
#[derive(Clone)]
pub struct StoredIdentity {
    pub cert_pem: String,
    pub key_pem: String,
}

impl std::fmt::Debug for StoredIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredIdentity")
            .field("cert_pem", &self.cert_pem)
            .finish_non_exhaustive()
    }
}

/// The node's state directory.
#[derive(Debug, Clone)]
pub struct StateDir {
    root: PathBuf,
}

impl StateDir {
    /// Opens `root`, creating it (mode 0700) when absent.
    pub fn open(root: &Path) -> Result<Self, StateError> {
        let io_err = |source| StateError::Io {
            path: root.to_path_buf(),
            source,
        };
        if !root.is_dir() {
            std::fs::create_dir_all(root).map_err(io_err)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
                    .map_err(io_err)?;
            }
        }
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    /// `tls.ca_dir` for a node.
    pub fn ca_dir(&self) -> PathBuf {
        self.root.join(CA_DIR)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// The stored identity: `None` before enrolment. Exactly one of the two
    /// files present is an error, never a reason to enrol again.
    pub fn identity(&self) -> Result<Option<StoredIdentity>, StateError> {
        let cert = self.read_opt(CERT_FILE)?;
        let key = self.read_opt(KEY_FILE)?;
        match (cert, key) {
            (Some(cert_pem), Some(key_pem)) => Ok(Some(StoredIdentity { cert_pem, key_pem })),
            (None, None) => Ok(None),
            (Some(_), None) => Err(StateError::Incomplete {
                dir: self.root.clone(),
                present: CERT_FILE,
                missing: KEY_FILE,
            }),
            (None, Some(_)) => Err(StateError::Incomplete {
                dir: self.root.clone(),
                present: KEY_FILE,
                missing: CERT_FILE,
            }),
        }
    }

    /// Writes the key (0600) and then the certificate, so an interrupted
    /// enrolment leaves a key without a certificate, which `identity`
    /// reports rather than treating as unenrolled.
    pub fn store_identity(&self, cert_pem: &str, key_pem: &str) -> Result<(), StateError> {
        self.write(KEY_FILE, key_pem.as_bytes(), 0o600)?;
        self.write(CERT_FILE, cert_pem.as_bytes(), 0o644)
    }

    /// Replaces the certificate after a renewal; the key stays.
    pub fn store_cert(&self, cert_pem: &str) -> Result<(), StateError> {
        self.write(CERT_FILE, cert_pem.as_bytes(), 0o644)
    }

    /// The highest flow `seq` reserved so far; 0 before any was.
    pub fn load_seq(&self) -> Result<u64, StateError> {
        match self.read_opt(SEQ_FILE)? {
            None => Ok(0),
            Some(text) => text.trim().parse().map_err(|_| StateError::BadSeq {
                path: self.file(SEQ_FILE),
                text,
            }),
        }
    }

    pub fn store_seq(&self, seq: u64) -> Result<(), StateError> {
        self.write(SEQ_FILE, format!("{seq}\n").as_bytes(), 0o644)
    }

    fn read_opt(&self, name: &str) -> Result<Option<String>, StateError> {
        let path = self.file(name);
        match std::fs::read_to_string(&path) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(StateError::Io { path, source }),
        }
    }

    /// Writes through a temporary file and a rename, so a reader never sees
    /// a partial file and a crash leaves the old one.
    fn write(
        &self,
        name: &str,
        contents: &[u8],
        #[allow(unused)] mode: u32,
    ) -> Result<(), StateError> {
        use std::io::Write as _;
        let path = self.file(name);
        let tmp = self.file(&format!(".{name}.tmp"));
        let io_err = |source| StateError::Io {
            path: path.clone(),
            source,
        };
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(mode);
        }
        let mut file = opts.open(&tmp).map_err(io_err)?;
        #[cfg(unix)]
        {
            // `mode` only applies to a file this call creates; a leftover
            // temporary from an earlier run keeps its old bits otherwise.
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(std::fs::Permissions::from_mode(mode))
                .map_err(io_err)?;
        }
        file.write_all(contents).map_err(io_err)?;
        file.sync_all().map_err(io_err)?;
        drop(file);
        std::fs::rename(&tmp, &path).map_err(io_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn identity_is_stored_with_a_private_key_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("state");
        let state = StateDir::open(&root).unwrap();
        assert!(state.identity().unwrap().is_none());
        state.store_identity("CERT", "KEY").unwrap();
        let id = state.identity().unwrap().unwrap();
        assert_eq!((id.cert_pem.as_str(), id.key_pem.as_str()), ("CERT", "KEY"));
        #[cfg(unix)]
        {
            assert_eq!(mode(&root), 0o700);
            assert_eq!(mode(&root.join(KEY_FILE)), 0o600);
        }
        assert!(!format!("{id:?}").contains("KEY"), "{id:?}");
        state.store_cert("CERT2").unwrap();
        assert_eq!(state.identity().unwrap().unwrap().cert_pem, "CERT2");
        assert_eq!(state.ca_dir(), root.join("ca"));
    }

    #[test]
    fn a_half_written_identity_is_an_error_not_a_fresh_start() {
        let dir = tempfile::tempdir().unwrap();
        let state = StateDir::open(dir.path()).unwrap();
        std::fs::write(dir.path().join(KEY_FILE), "KEY").unwrap();
        let err = state.identity().unwrap_err();
        assert!(matches!(
            err,
            StateError::Incomplete {
                present: KEY_FILE,
                missing: CERT_FILE,
                ..
            }
        ));
        std::fs::remove_file(dir.path().join(KEY_FILE)).unwrap();
        std::fs::write(dir.path().join(CERT_FILE), "CERT").unwrap();
        assert!(matches!(
            state.identity(),
            Err(StateError::Incomplete {
                present: CERT_FILE,
                ..
            })
        ));
    }

    #[test]
    fn flow_seq_persists_and_garbage_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = StateDir::open(dir.path()).unwrap();
        assert_eq!(state.load_seq().unwrap(), 0);
        state.store_seq(4096).unwrap();
        assert_eq!(state.load_seq().unwrap(), 4096);
        std::fs::write(dir.path().join(SEQ_FILE), "lots\n").unwrap();
        assert!(matches!(state.load_seq(), Err(StateError::BadSeq { .. })));
    }
}
