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
pub use body::{Body, BodySender, Buffered, CHANNEL_DEPTH};
pub(crate) use error::reject;
pub use error::{BodyError, DriveError, ParseError, Reason, WriteError};
pub(crate) use framing::{parse_content_length, plan_body};
pub(crate) use headers::parse_field_line;
pub use headers::{
    Headers, RESERVED, check_trailer_fields, connection_tokens, is_forbidden_trailer, is_reserved,
    requested_upgrade, validate_response_trailers,
};
pub use limits::{HttpFlags, Limits};
pub use message::{
    CanonicalRequest, CanonicalResponse, RequestMeta, ResponseMeta, TargetForm, Version,
    status_forbids_body,
};
pub use method::Method;

pub use crate::url::{Path, Query};
