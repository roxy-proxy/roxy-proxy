//! [`RotatingFile`]: an append-only file with size-based rotation.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::Destination;

/// Rotation settings for a [`RotatingFile`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RotateOptions {
    /// Rotate once the file reaches this size (checked at batch
    /// boundaries, so a file may exceed it by up to one batch). `None`:
    /// never rotate.
    pub max_file_bytes: Option<u64>,
    /// Keep at most this many rotated files (oldest deleted first). `None`:
    /// keep all.
    pub max_files: Option<usize>,
    /// Gzip rotated files in the background (`<name>.gz`).
    pub compress: bool,
}

/// An append-only file that rotates by size: when it reaches
/// [`RotateOptions::max_file_bytes`] at a batch boundary it is renamed to
/// `<path>.<UTC timestamp>-<seq>` (e.g. `flow.jsonl.20261003T184200.123Z-0000`) and a
/// new file is opened at `path`. Rotated files sort by name in rotation
/// order.
///
/// Rotation and reopen errors are returned to the writer, which holds
/// traffic and retries; nothing written is ever lost. If the rename succeeds
/// but opening the new file fails, writes continue into the renamed file
/// until the retry succeeds.
#[derive(Debug)]
pub struct RotatingFile {
    path: PathBuf,
    file: File,
    size: u64,
    opts: RotateOptions,
    /// Stamp and sequence of the last rotated name.
    last: Option<(String, u32)>,
    /// Test hook: the next N rotations fail.
    #[cfg(test)]
    fail_rotations: Arc<AtomicUsize>,
}

fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

impl RotatingFile {
    /// Opens (creating if needed) `path` for appending.
    pub fn open(path: &Path, opts: RotateOptions) -> io::Result<Self> {
        let file = open_append(path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            path: path.to_path_buf(),
            file,
            size,
            opts,
            last: None,
            #[cfg(test)]
            fail_rotations: Arc::default(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn file_name(&self) -> String {
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    fn dir(&self) -> PathBuf {
        match self.path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        }
    }

    /// The next rotated name: `<name>.<UTC stamp>-<seq>`. Names are
    /// strictly increasing within a process (if the clock steps back, the
    /// previous stamp is reused with a higher sequence), so sorting by name
    /// is rotation order, and a name freed by pruning is never reused out of
    /// order. Names that exist already (plain or compressed, e.g. from an
    /// earlier run) are skipped.
    fn rotated_name(&mut self) -> PathBuf {
        let now = chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ").to_string();
        let (stamp, mut seq) = match &self.last {
            Some((last, seq)) if *last >= now => (last.clone(), seq + 1),
            _ => (now, 0),
        };
        let dir = self.dir();
        let file = self.file_name();
        loop {
            let n = format!("{file}.{stamp}-{seq:04}");
            if !dir.join(&n).exists() && !dir.join(format!("{n}.gz")).exists() {
                self.last = Some((stamp, seq));
                return dir.join(n);
            }
            seq += 1;
        }
    }

    fn rotate(&mut self) -> io::Result<()> {
        #[cfg(test)]
        if self
            .fail_rotations
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(io::Error::other("injected rotation failure"));
        }
        let target = self.rotated_name();
        match fs::rename(&self.path, &target) {
            Ok(()) => {}
            // Already renamed by an earlier attempt whose reopen failed, or
            // removed externally: just open a fresh file.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        self.file = open_append(&self.path)?;
        self.size = 0;
        tracing::info!(path = %self.path.display(), rotated = %target.display(), "log file rotated");
        if self.opts.compress && target.exists() {
            let keep = self.opts.max_files;
            let me = self.clone_for_prune();
            std::thread::Builder::new()
                .name("roxy-log-gzip".into())
                .spawn(move || {
                    if let Err(e) = gzip(&target) {
                        tracing::warn!(file = %target.display(), error = %e, "compressing a rotated log failed; left uncompressed");
                    }
                    me.prune(keep);
                })?;
        } else {
            self.clone_for_prune().prune(self.opts.max_files);
        }
        Ok(())
    }

    fn clone_for_prune(&self) -> Pruner {
        Pruner {
            dir: self.dir(),
            prefix: format!("{}.", self.file_name()),
        }
    }
}

/// Deletes the oldest rotated files beyond `max_files`.
struct Pruner {
    dir: PathBuf,
    prefix: String,
}

impl Pruner {
    fn prune(&self, max_files: Option<usize>) {
        let Some(max) = max_files else { return };
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return;
        };
        // Rotated files, keyed without `.gz` so a file being compressed
        // (both forms present) counts once.
        let mut keys: Vec<String> = entries
            .filter_map(Result::ok)
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.starts_with(&self.prefix) && n.len() > self.prefix.len())
            // An archive being written is not a rotated file yet.
            .filter(|n| Path::new(n).extension().is_none_or(|e| e != "tmp"))
            .map(|n| n.strip_suffix(".gz").map(str::to_owned).unwrap_or(n))
            .collect();
        keys.sort();
        keys.dedup();
        let excess = keys.len().saturating_sub(max);
        for key in &keys[..excess] {
            for name in [key.clone(), format!("{key}.gz")] {
                let p = self.dir.join(&name);
                match fs::remove_file(&p) {
                    Ok(()) => tracing::info!(file = %p.display(), "old log file removed"),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => {
                        tracing::warn!(file = %p.display(), error = %e, "removing an old log file failed");
                    }
                }
            }
        }
    }
}

/// `<file>` → `<file>.gz`, then removes `<file>`. Writes to a temporary name
/// first so a half-written archive is never mistaken for a complete one.
fn gzip(path: &Path) -> io::Result<()> {
    let gz = path.with_file_name(format!(
        "{}.gz",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    let tmp = gz.with_extension("gz.tmp");
    {
        let mut input = File::open(path)?;
        let out = File::create(&tmp)?;
        let mut enc = flate2::write::GzEncoder::new(out, flate2::Compression::default());
        io::copy(&mut input, &mut enc)?;
        enc.finish()?.sync_all()?;
    }
    fs::rename(&tmp, &gz)?;
    fs::remove_file(path)
}

impl Destination for RotatingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.file.write(buf)?;
        self.size += n as u64;
        Ok(n)
    }

    fn end_batch(&mut self) -> io::Result<()> {
        self.file.flush()?;
        if self.opts.max_file_bytes.is_some_and(|max| self.size >= max) {
            self.rotate()?;
        }
        Ok(())
    }

    fn reopen(&mut self) -> io::Result<()> {
        self.file = open_append(&self.path)?;
        self.size = self.file.metadata()?.len();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LogWriter;
    use crate::writer::tests::opts;
    use std::io::Read;
    use std::task::{Context, Waker};
    use std::time::{Duration, Instant};

    fn rotated(dir: &Path, name: &str) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                let n = p.file_name().unwrap().to_string_lossy();
                n.starts_with(&format!("{name}.")) && !n.ends_with(".tmp")
            })
            .collect();
        v.sort();
        v
    }

    fn read(p: &Path) -> String {
        let mut s = String::new();
        if p.extension().is_some_and(|e| e == "gz") {
            flate2::read::GzDecoder::new(File::open(p).unwrap())
                .read_to_string(&mut s)
                .unwrap();
        } else {
            File::open(p).unwrap().read_to_string(&mut s).unwrap();
        }
        s
    }

    /// Every rotated file, oldest first, then the live file.
    fn all_lines(dir: &Path, name: &str) -> Vec<String> {
        let mut files = rotated(dir, name);
        files.push(dir.join(name));
        files
            .iter()
            .flat_map(|p| read(p).lines().map(str::to_owned).collect::<Vec<_>>())
            .collect()
    }

    #[test]
    fn concurrent_emitters_across_rotations_lose_and_duplicate_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flow.jsonl");
        let dest = RotatingFile::open(
            &path,
            RotateOptions {
                max_file_bytes: Some(4096),
                max_files: None,
                compress: false,
            },
        )
        .unwrap();
        let w = std::sync::Arc::new(LogWriter::spawn("t", dest, opts(1 << 20)).unwrap());
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let w = w.clone();
                std::thread::spawn(move || {
                    for i in 0..2000 {
                        w.append(format!("{{\"t\":{t},\"i\":{i}}}\n").as_bytes());
                        // Force batch boundaries: emitters that outrun the
                        // writer would otherwise merge into a few large
                        // batches and starve rotation.
                        if i % 250 == 249 {
                            assert!(w.flush());
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert!(w.flush());
        let files = rotated(dir.path(), "flow.jsonl");
        assert!(!files.is_empty(), "never rotated");
        let lines = all_lines(dir.path(), "flow.jsonl");
        assert_eq!(lines.len(), 16_000);
        for t in 0..8 {
            let mine: Vec<usize> = lines
                .iter()
                .filter_map(|l| {
                    let v: Vec<&str> = l.trim_matches(['{', '}']).split(',').collect();
                    (v[0] == format!("\"t\":{t}"))
                        .then(|| v[1].trim_start_matches("\"i\":").parse().unwrap())
                })
                .collect();
            assert_eq!(
                mine,
                (0..2000).collect::<Vec<_>>(),
                "thread {t}: order, no gaps, no duplicates"
            );
        }
    }

    #[test]
    fn failing_rotation_holds_traffic_then_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flow.jsonl");
        let dest = RotatingFile::open(
            &path,
            RotateOptions {
                max_file_bytes: Some(10),
                ..RotateOptions::default()
            },
        )
        .unwrap();
        let failures = dest.fail_rotations.clone();
        failures.store(30, Ordering::Release);
        let w = LogWriter::spawn("t", dest, opts(1 << 20)).unwrap();
        w.append(b"first record that triggers rotation\n");
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let deadline = Instant::now() + Duration::from_secs(5);
        while w.poll_ready(&mut cx).is_ready() {
            assert!(
                Instant::now() < deadline,
                "rotation failure never held traffic"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        // Appends while failing are kept, not dropped.
        w.append(b"second record\n");
        assert!(w.flush(), "recovers once rotation succeeds");
        assert!(w.poll_ready(&mut cx).is_ready());
        assert_eq!(failures.load(Ordering::Acquire), 0);
        assert_eq!(
            all_lines(dir.path(), "flow.jsonl"),
            ["first record that triggers rotation", "second record"]
        );
    }

    #[test]
    fn prunes_to_max_files_and_compresses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flow.jsonl");
        let dest = RotatingFile::open(
            &path,
            RotateOptions {
                max_file_bytes: Some(1),
                max_files: Some(3),
                compress: true,
            },
        )
        .unwrap();
        let w = LogWriter::spawn("t", dest, opts(1 << 20)).unwrap();
        for i in 0..10 {
            w.append(format!("record {i}\n").as_bytes());
            assert!(w.flush());
        }
        // Compression and pruning run in the background.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let files = rotated(dir.path(), "flow.jsonl");
            let all_gz = files
                .iter()
                .all(|p| p.extension().is_some_and(|e| e == "gz"));
            if files.len() == 3 && all_gz {
                break;
            }
            assert!(Instant::now() < deadline, "{files:?}");
            std::thread::sleep(Duration::from_millis(20));
        }
        // The newest rotated files are kept.
        let kept: Vec<String> = rotated(dir.path(), "flow.jsonl")
            .iter()
            .map(|p| read(p).trim().to_owned())
            .collect();
        assert_eq!(kept, ["record 7", "record 8", "record 9"]);
    }

    #[test]
    fn reopen_follows_external_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flow.jsonl");
        let dest = RotatingFile::open(&path, RotateOptions::default()).unwrap();
        let w = LogWriter::spawn("t", dest, opts(1 << 20)).unwrap();
        w.append(b"before\n");
        assert!(w.flush());
        // logrotate-style: move the file away, then signal.
        fs::rename(&path, dir.path().join("moved.jsonl")).unwrap();
        w.reopen();
        w.append(b"after\n");
        assert!(w.flush());
        assert_eq!(read(&dir.path().join("moved.jsonl")), "before\n");
        assert_eq!(read(&path), "after\n");
    }
}
