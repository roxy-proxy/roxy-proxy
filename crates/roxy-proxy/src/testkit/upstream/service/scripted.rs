//! A service driven by a test, so approval happens only after the test
//! has observed the client's preliminary response on the wire.

use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use super::{ServiceLog, binary, dir_name, lock, text};

pub(crate) struct Script {
    tx: mpsc::UnboundedSender<Message>,
    rx: mpsc::UnboundedReceiver<Message>,
    id: u32,
}

impl ServiceLog {
    pub(crate) async fn script(&self) -> Script {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(script) = lock(&self.scripts).pop_front() {
                    return script;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the scripted service connects")
    }
}

impl Script {
    pub(super) fn new(
        tx: mpsc::UnboundedSender<Message>,
        rx: mpsc::UnboundedReceiver<Message>,
    ) -> Self {
        Self { tx, rx, id: 0 }
    }

    pub(crate) fn send(&self, value: Value) {
        self.tx.send(text(self.id, value)).unwrap();
    }

    /// These scripts send less than one credit window per direction.
    pub(crate) fn bytes(&self, dir: u8, bytes: &[u8]) {
        assert!(bytes.len() < usize::try_from(super::WINDOW).unwrap());
        self.tx.send(binary(self.id, dir, bytes)).unwrap();
    }

    async fn next(&mut self) -> Message {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let m = self.rx.recv().await.expect("the service is connected");
                match &m {
                    Message::Text(t) => {
                        let v: Value = serde_json::from_str(t).unwrap();
                        if v["type"] == "credit" {
                            continue;
                        }
                    }
                    Message::Binary(b) => self.send(json!({
                        "type": "credit", "dir": dir_name(b[4]), "bytes": b.len() - 5,
                    })),
                    Message::Ping(_) | Message::Pong(_) | Message::Close(_) | Message::Frame(_) => {
                        panic!("unexpected service message: {m:?}");
                    }
                }
                return m;
            }
        })
        .await
        .expect("the next service message arrives")
    }

    pub(crate) async fn control(&mut self, kind: &str) -> Value {
        let Message::Text(t) = self.next().await else {
            panic!("expected {kind}");
        };
        let v: Value = serde_json::from_str(&t).unwrap();
        assert_eq!(v["type"], kind, "{v}");
        if kind == "open" {
            self.id = u32::try_from(v["stream"].as_u64().unwrap()).unwrap();
        }
        v
    }

    pub(crate) async fn body(&mut self, dir: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            match self.next().await {
                Message::Binary(b) => {
                    assert_eq!(b[4], dir);
                    bytes.extend_from_slice(&b[5..]);
                }
                Message::Text(t) => {
                    let v: Value = serde_json::from_str(&t).unwrap();
                    assert_eq!(v["type"], format!("{}_end", dir_name(dir)), "{v}");
                    assert!(v["error"].is_null(), "{v}");
                    return bytes;
                }
                m @ (Message::Ping(_)
                | Message::Pong(_)
                | Message::Close(_)
                | Message::Frame(_)) => {
                    panic!("unexpected body message: {m:?}");
                }
            }
        }
    }

    pub(crate) async fn chunk(&mut self, dir: u8) -> Vec<u8> {
        let Message::Binary(b) = self.next().await else {
            panic!("expected body data");
        };
        assert_eq!(b[4], dir);
        b[5..].to_vec()
    }
}
