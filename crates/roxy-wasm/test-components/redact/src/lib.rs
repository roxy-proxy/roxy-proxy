//! An example roxy addon: replaces configured literal strings in request
//! and response bodies, chunk by chunk, as they stream.
//!
//! ```yaml
//! addons:
//!   - name: redact
//!     kind: wasm
//!     path: /etc/roxy/addons/redact.wasm
//!     config:
//!       needles: ["sk-live-1234", "hunter2"]
//!       replacement: "[redacted]"
//! ```
//!
//! A needle can straddle two chunks, so the transform holds back the last
//! `longest needle - 1` bytes of each chunk until the next one (or the end
//! of the body) arrives. Nothing else is buffered.

use roxy_addon::prelude::*;

/// The layer: its configuration, shared by every exchange.
pub struct Redact {
    needles: Vec<Vec<u8>>,
    replacement: Vec<u8>,
}

impl Layer for Redact {
    fn init(config: &str) -> Result<Self, String> {
        let config: serde_json::Value =
            serde_json::from_str(config).map_err(|e| format!("config: {e}"))?;
        let needles: Vec<Vec<u8>> = config["needles"]
            .as_array()
            .ok_or("config.needles must be a list of strings")?
            .iter()
            .map(|n| match n.as_str() {
                Some(s) if !s.is_empty() => Ok(s.as_bytes().to_vec()),
                _ => Err("config.needles must be non-empty strings".to_owned()),
            })
            .collect::<Result<_, _>>()?;
        let replacement = config["replacement"]
            .as_str()
            .unwrap_or("[redacted]")
            .as_bytes()
            .to_vec();
        Ok(Self {
            needles,
            replacement,
        })
    }

    fn handle(&mut self, req: Request, next: Next) -> Response {
        // With nothing to redact the bodies pass through untouched.
        if self.needles.is_empty() {
            return next.run(req);
        }
        let req = req.map_body(|b| b.pipe(self.redactor()));
        let resp = next.run(req);
        resp.map_body(|b| b.pipe(self.redactor()))
    }
}

roxy_addon::export!(Redact);

impl Redact {
    fn redactor(&self) -> Redactor {
        Redactor {
            needles: self.needles.clone(),
            replacement: self.replacement.clone(),
            tail: Vec::new(),
        }
    }
}

/// The streaming transform for one body.
pub struct Redactor {
    needles: Vec<Vec<u8>>,
    replacement: Vec<u8>,
    /// Bytes held back because a needle could start in them.
    tail: Vec<u8>,
}

impl Redactor {
    fn keep(&self) -> usize {
        self.needles.iter().map(Vec::len).max().unwrap_or(1) - 1
    }

    /// Replaces every needle in `buf`, returning the result and how many
    /// bytes at the end of `buf` were left unexamined (they could begin a
    /// needle that continues in the next chunk).
    fn scan(&self, buf: &[u8], hold: usize) -> (Vec<u8>, usize) {
        let mut out = Vec::with_capacity(buf.len());
        let mut i = 0;
        let limit = buf.len().saturating_sub(hold);
        'outer: while i < limit {
            for n in &self.needles {
                if buf[i..].starts_with(n) {
                    out.extend_from_slice(&self.replacement);
                    i += n.len();
                    continue 'outer;
                }
            }
            out.push(buf[i]);
            i += 1;
        }
        (out, buf.len() - i)
    }
}

impl ChunkTransform for Redactor {
    fn chunk(&mut self, chunk: Vec<u8>) -> Vec<u8> {
        let mut buf = std::mem::take(&mut self.tail);
        buf.extend_from_slice(&chunk);
        let (out, held) = self.scan(&buf, self.keep());
        self.tail = buf[buf.len() - held..].to_vec();
        out
    }

    fn finish(&mut self) -> Vec<u8> {
        let buf = std::mem::take(&mut self.tail);
        self.scan(&buf, 0).0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redact(input: &[u8], chunk: usize) -> Vec<u8> {
        let layer =
            Redact::init(r#"{"needles": ["secret", "sk-1234"], "replacement": "***"}"#).unwrap();
        let mut r = layer.redactor();
        let mut out = Vec::new();
        for c in input.chunks(chunk) {
            out.extend(r.chunk(c.to_vec()));
        }
        out.extend(r.finish());
        out
    }

    #[test]
    fn redacts_across_chunk_boundaries() {
        let input = b"my secret is sk-1234, not secrets";
        for chunk in 1..=input.len() {
            assert_eq!(
                redact(input, chunk),
                b"my *** is ***, not ***s",
                "chunk size {chunk}"
            );
        }
    }

    #[test]
    fn leaves_other_bytes_alone() {
        assert_eq!(redact(b"nothing to see", 3), b"nothing to see");
        assert_eq!(redact(b"", 3), b"");
        assert_eq!(redact(b"secre", 2), b"secre");
    }

    #[test]
    fn rejects_bad_config() {
        assert!(Redact::init("null").is_err());
        assert!(Redact::init(r#"{"needles": [""]}"#).is_err());
    }
}
