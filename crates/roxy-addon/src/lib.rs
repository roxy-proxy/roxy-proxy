//! Write [roxy](https://github.com/roxy-proxy/roxy-proxy) addon layers in
//! Rust.
//!
//! A layer sits in an exchange's layer stack above roxy's rules. It gets
//! each request with a streaming body, may pass a request down once with
//! [`Next::run`], and returns a response, whose body also streams:
//!
//! ```ignore
//! use roxy_addon::prelude::*;
//!
//! struct Shout;
//!
//! impl Layer for Shout {
//!     fn init(_config: &str) -> Result<Self, String> {
//!         Ok(Shout)
//!     }
//!
//!     fn handle(&mut self, req: Request, next: Next) -> Response {
//!         let resp = next.run(req);
//!         resp.map_body(|b| b.transform(|mut chunk| {
//!             chunk.make_ascii_uppercase();
//!             chunk
//!         }))
//!     }
//! }
//!
//! roxy_addon::export!(Shout);
//! ```
//!
//! Build with `cargo build --target wasm32-wasip2 --release` (the crate
//! type must be `cdylib`); the output is a component roxy loads with
//! `addons: [{kind: wasm, path: ...}]`.
//!
//! A panic traps the layer, and roxy fails the exchange closed. That is the
//! intended way to give up.

#[allow(unsafe_code, missing_docs, clippy::all, clippy::pedantic)]
pub mod bindings;
mod body;
pub mod flow;
mod message;
mod pump;

use std::any::Any;
use std::cell::RefCell;

pub use body::{Body, BodyError, ChunkTransform};
pub use message::{Error, Headers, Next, Request, Response, call_endpoint};

/// The common imports for writing a layer.
pub mod prelude {
    pub use crate::flow;
    pub use crate::{
        Body, BodyError, ChunkTransform, Headers, Layer, Next, Request, Response, call_endpoint,
    };
}

/// A layer. One value is created per instance by [`Layer::init`] and
/// handles that instance's exchanges, one at a time.
pub trait Layer: Sized + 'static {
    /// Creates the layer from its `config:` value (a JSON document, `"null"`
    /// when unset). An error fails roxy's config load.
    fn init(config: &str) -> Result<Self, String>;

    /// Handles one exchange. Call `next.run(req)` (at most once) to pass a
    /// request down, or return a response without it to answer directly.
    fn handle(&mut self, req: Request, next: Next) -> Response;
}

thread_local! {
    static LAYER: RefCell<Option<Box<dyn Any>>> = const { RefCell::new(None) };
}

/// Used by [`export!`]; not part of the API.
#[doc(hidden)]
pub mod __private {
    pub use crate::bindings::exports::roxy::addon::handler::Guest as HandlerGuest;
    pub use crate::bindings::exports::roxy::addon::init::Guest as InitGuest;
    pub use crate::bindings::roxy::addon::types::RequestHead;
    pub use crate::bindings::wasi::io::streams::InputStream;

    use super::{LAYER, Layer, Next, Request, message};

    pub fn init<L: Layer>() -> Result<(), String> {
        let layer = L::init(&crate::flow::config())?;
        LAYER.with(|l| *l.borrow_mut() = Some(Box::new(layer)));
        Ok(())
    }

    pub fn handle<L: Layer>(head: RequestHead, body: InputStream) {
        let req = Request::from_wire(head, body);
        let resp = LAYER.with(|l| {
            let mut slot = l.borrow_mut();
            let layer = slot
                .as_mut()
                .and_then(|b| b.downcast_mut::<L>())
                .expect("layer not initialised");
            layer.handle(req, Next::new())
        });
        message::respond(resp);
    }
}

/// Exports a [`Layer`] type as the component's layer.
#[macro_export]
macro_rules! export {
    ($layer:ty) => {
        #[doc(hidden)]
        pub struct __RoxyAddonExport;

        impl $crate::__private::InitGuest for __RoxyAddonExport {
            fn init() -> ::core::result::Result<(), ::std::string::String> {
                $crate::__private::init::<$layer>()
            }
        }

        impl $crate::__private::HandlerGuest for __RoxyAddonExport {
            fn handle(
                req: $crate::__private::RequestHead,
                body: $crate::__private::InputStream,
            ) {
                $crate::__private::handle::<$layer>(req, body)
            }
        }

        // The component exports only exist on wasm; on other targets the
        // crate still builds (for native unit tests of the layer's logic).
        #[cfg(target_arch = "wasm32")]
        $crate::bindings::export!(__RoxyAddonExport with_types_in $crate::bindings);
    };
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    /// The crate carries its own copy of the WIT package (so it can be
    /// published); it must match the workspace's.
    #[test]
    fn wit_matches_workspace() {
        let here = Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace = here.join("../../wit");
        if !workspace.exists() {
            return; // published crate
        }
        let mut files = Vec::new();
        collect(&workspace, &mut files);
        assert_ne!(files.len(), 0);
        for f in files {
            let rel = f.strip_prefix(&workspace).unwrap();
            let ours = here.join("wit").join(rel);
            assert_eq!(
                std::fs::read(&f).unwrap(),
                std::fs::read(&ours).unwrap_or_default(),
                "crates/roxy-addon/wit/{} differs from wit/{}; copy it over",
                rel.display(),
                rel.display()
            );
        }
    }

    fn collect(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                collect(&p, out);
            } else {
                out.push(p);
            }
        }
    }
}
