//! Canonical HTTP model.

mod authority;
mod body;
mod error;
mod framing;
mod headers;
mod limits;
mod message;
mod method;

pub use authority::{Authority, Host, Scheme};
pub use body::{Body, BodySender, CHANNEL_DEPTH};
pub(crate) use error::reject;
pub use error::{BodyError, ParseError, Reason, WriteError};
pub(crate) use framing::{parse_content_length, plan_body};
pub use headers::{Headers, RESERVED, is_forbidden_trailer, is_reserved};
pub(crate) use headers::{connection_tokens, parse_field_line};
pub use limits::{HttpFlags, Limits};
pub use message::{
    CanonicalRequest, CanonicalResponse, RequestMeta, ResponseMeta, TargetForm, Version,
    status_forbids_body,
};
pub use method::Method;

pub use crate::url::{Path, Query};
