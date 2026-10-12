# Reporting a vulnerability

roxy is a security boundary, so a bug that lets a request past the policy,
leaks a secret, or crashes the proxy from the network is a vulnerability.
Please report it privately rather than in a public issue:

- Use GitHub's private vulnerability reporting for this repository:
  https://github.com/roxy-proxy/roxy-proxy/security/advisories/new

Include the roxy version (`roxy --version`), a config and policy that show
the problem, and what you expected roxy to do instead. We will acknowledge
the report and keep you informed as it is fixed.

What roxy does and does not defend against is written down in the
[threat model](https://roxy-proxy.github.io/roxy-proxy/design/threat-model);
behaviour that matches it is not a vulnerability, though it may be worth an
issue.
