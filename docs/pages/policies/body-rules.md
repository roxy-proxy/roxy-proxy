# Body rules

`body.text` and `response.body.text` are the only fields that buffer. For an
exchange whose other predicates match, roxy collects the body up to
`limits.max_inspect_body_bytes` (1 MiB), evaluates, then streams the bytes
on. A larger body **fails closed** (`_fail_closed`, reason
`body_too_large_to_inspect`). Raise the cap to inspect larger bodies, or
scope the rule (`body.size != null and body.size < 1mb and ...`) so it
short-circuits before the body is touched. Rules that do not read a body
never buffer.

The text is the body decoded by its `content-encoding` (`gzip`, `deflate`,
`br`, `zstd`, stacked or not; [HTTP](/reference/http#content-codings)), then read
as lossy UTF-8. Decoding is for the rules only: the bytes forwarded are the
bytes received. The cap applies to the decoded text too, so a small body
that inflates past it fails closed with `body_too_large_to_inspect`. A body
that cannot be decoded fails closed as well: `body_decode_failed` for
corrupt or truncated data or bytes after the end of the stream,
`unsupported_content_encoding` for a coding roxy does not know.
