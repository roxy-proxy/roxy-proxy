//! The state dir: the node token, the flow sequence counter, the
//! interception CA's directory and the quarantine marker. Nothing else is
//! ever written here; secrets and the rendered config stay in memory. A
//! roxy run from a config file uses the same layout for the marker alone.
//!
//! Every file this dir replaces (token, flow sequence, marker) goes
//! through [`write_atomic`], the one place that knows how to replace a file
//! so that a crash at any point leaves either the old file or the new one,
//! with the mode asked for. The CA dir's files are created once and never
//! replaced, so `roxy-tls` writes them exclusively instead.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

/// The node token record, mode 0600.
pub const TOKEN_FILE: &str = "node.token";
/// The flow `seq` counter: the highest value reserved so far.
pub const SEQ_FILE: &str = "flow.seq";
/// Where the interception CA lives (`tls.ca_dir`).
pub const CA_DIR: &str = "ca";
/// The quarantine marker: present, with the incident as JSON, while the
/// process is quarantined. Written and removed by the proxy.
pub const QUARANTINE_FILE: &str = "quarantine";

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{}: not a flow sequence number: {text:?}", path.display())]
    BadSeq { path: PathBuf, text: String },
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

    /// The quarantine marker's path.
    pub fn quarantine_marker(&self) -> PathBuf {
        self.file(QUARANTINE_FILE)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// The stored node token record, as written: `None` before enrolment.
    pub fn node_token(&self) -> Result<Option<String>, StateError> {
        self.read_opt(TOKEN_FILE)
    }

    /// Writes the node token record, readable by the owner alone.
    pub fn store_node_token(&self, record: &str) -> Result<(), StateError> {
        self.write(TOKEN_FILE, record.as_bytes(), 0o600)
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

    fn write(&self, name: &str, contents: &[u8], mode: u32) -> Result<(), StateError> {
        let path = self.file(name);
        match write_atomic(&path, contents, mode) {
            Ok(()) => Ok(()),
            Err(source) => Err(StateError::Io { path, source }),
        }
    }
}

/// Writes `contents` to `path` with `mode` through a temporary file in the
/// same directory and a rename, so a reader sees the old file or the new one
/// and never a partial one. The file and then its directory are synced, so
/// the new file is durable when this returns.
pub fn write_atomic(path: &Path, contents: &[u8], #[allow(unused)] mode: u32) -> io::Result<()> {
    use std::io::Write as _;
    let tmp = temp_path(path);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(mode);
    }
    let mut file = opts.open(&tmp)?;
    #[cfg(unix)]
    {
        // `mode` only applies to a file this call creates; a leftover
        // temporary from an earlier run keeps its old bits otherwise.
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    }
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)?;
    sync_parent(path)
}

/// A rename or unlink is durable once the directory holding it is.
pub fn sync_parent(path: &Path) -> io::Result<()> {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => std::fs::File::open(dir)?.sync_all(),
        _ => Ok(()),
    }
}

/// `.name.tmp` beside `path`: in the same directory, so the rename is one
/// filesystem operation.
fn temp_path(path: &Path) -> PathBuf {
    let mut name = OsString::from(".");
    name.push(path.file_name().unwrap_or_default());
    name.push(".tmp");
    path.with_file_name(name)
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
    fn the_node_token_is_stored_privately_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("state");
        let state = StateDir::open(&root).unwrap();
        assert!(state.node_token().unwrap().is_none());
        state.store_node_token("TOKEN").unwrap();
        assert_eq!(state.node_token().unwrap().as_deref(), Some("TOKEN"));
        #[cfg(unix)]
        {
            assert_eq!(mode(&root), 0o700);
            assert_eq!(mode(&root.join(TOKEN_FILE)), 0o600);
        }
        state.store_node_token("TOKEN2").unwrap();
        assert_eq!(state.node_token().unwrap().as_deref(), Some("TOKEN2"));
        #[cfg(unix)]
        assert_eq!(mode(&root.join(TOKEN_FILE)), 0o600);
        assert_eq!(state.ca_dir(), root.join("ca"));
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

    #[cfg(unix)]
    #[test]
    fn a_reused_temporary_is_made_private_before_it_is_written() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.token");
        let tmp = temp_path(&path);
        std::fs::write(&tmp, "stale").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_atomic(&path, b"TOKEN", 0o600).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"TOKEN");
        assert_eq!(mode(&path), 0o600);
        assert!(!tmp.exists());
    }

    #[test]
    fn the_target_keeps_its_old_contents_until_the_new_file_is_complete() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flow.seq");
        std::fs::write(&path, "old").unwrap();
        // A temporary that cannot be opened fails the write before the
        // rename; the target must not have been touched on the way.
        let tmp = temp_path(&path);
        std::fs::create_dir(&tmp).unwrap();
        write_atomic(&path, b"new", 0o644).unwrap_err();
        assert_eq!(std::fs::read(&path).unwrap(), b"old");
        std::fs::remove_dir(&tmp).unwrap();
        write_atomic(&path, b"new", 0o644).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert!(!tmp.exists());
    }
}
