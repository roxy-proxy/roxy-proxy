//! Canonical HTTP model (`DESIGN.md` §5.2, §5.6).

mod authority;
mod body;
mod error;
mod headers;
mod limits;
mod message;
mod method;

pub use authority::{Authority, Host, Scheme};
pub use body::{Body, BodySender, CHANNEL_DEPTH};
pub(crate) use error::reject;
pub use error::{BodyError, ParseError, Reason, WriteError};
pub use headers::{Headers, RESERVED, is_reserved};
pub(crate) use headers::{connection_tokens, validate_value};
pub use limits::{HttpFlags, Limits};
pub use message::{
    CanonicalRequest, CanonicalResponse, RequestMeta, ResponseMeta, TargetForm, Version,
    status_forbids_body,
};
pub use method::Method;

pub use crate::url::{Path, Query};
