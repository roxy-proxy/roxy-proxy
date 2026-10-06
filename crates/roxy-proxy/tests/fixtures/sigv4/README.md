# SigV4 known-answer vectors

Cases from the AWS SigV4 signing test suite, as shipped with the
`aws-sigv4` crate (`aws-signing-test-suite/v4`, itself taken from
<https://github.com/awslabs/aws-c-auth/tree/v0.9.0/tests/aws-signing-test-suite>).
Each case keeps its `context.json` (credentials, region, service,
timestamp), `request.txt` (the unsigned request) and
`header-signed-request.txt` (the expected signed request). The tests in
`src/sign.rs` sign `request.txt` through roxy's signer and compare the
`Authorization` and `X-Amz-*` fields with the expected request.

Only cases whose signed headers roxy would also sign are vendored: roxy
never signs `content-length`, so suite cases that sign it do not apply.
