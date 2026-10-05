# Body rules

`body.text` and `response.body.text` are the only fields that buffer. If
any rule reads `body.text`, roxy collects every request body up to
`limits.max_inspect_body_bytes` (1 MiB) before the head decision, evaluates,
then streams the bytes on; `response.body.text` does the same for every
response body. A body over the cap is **unavailable**, and a rule that
reads it **fails closed** (`_fail_closed`, reason
`body_too_large_to_inspect`). Raise the cap to inspect larger bodies, or
scope the rule (`body.size != null and body.size < 1mb and ...`) so it
short-circuits before reading the text: that avoids the fail-closed, not
the buffering. A policy with no rule reading a body never buffers.

The text is the body decoded by its `content-encoding` (`gzip`, `deflate`,
`br`, `zstd`, stacked or not; [HTTP](/reference/http#content-codings)), then read
as lossy UTF-8. Decoding is for the rules only: the bytes forwarded are the
bytes received. The cap applies to the decoded text too, so a small body
that inflates past it fails closed with `body_too_large_to_inspect`. A body
that cannot be decoded fails closed as well: `body_decode_failed` for
corrupt or truncated data or bytes after the end of the stream,
`unsupported_content_encoding` for a coding roxy does not know.
