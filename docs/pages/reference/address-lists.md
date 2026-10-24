# Address floor and lists

Rules decide by name. The address floor decides by IP address: before
roxy connects to an upstream, it checks every address the name resolved
to. Private addresses are refused by default, and address lists let you
refuse more. The settings are under `upstream` and `address_lists`
([upstream](/reference/upstream)).

## Address floor

roxy refuses to connect to an address if:

1. it is in `deny_cidrs`, which nothing can override; or
2. it is in one of the private ranges below, `deny_private_ranges` is on
   (the default), the address is not in `allow_cidrs`, and the rule that
   allowed the request does not say `private_ok: true`; or
3. it is in one of the lists named in `deny_lists`, which nothing can
   override.

| class | ranges |
|---|---|
| `unspecified` | `0.0.0.0/8`, `::` |
| `private` | `10/8`, `172.16/12`, `192.168/16` (RFC 1918) |
| `shared` | `100.64/10` (CGNAT) |
| `loopback` | `127/8`, `::1` |
| `link_local` | `169.254/16`, `fe80::/10` |
| `documentation` | `192.0.2/24`, `198.51.100/24`, `203.0.113/24`, `2001:db8::/32` |
| `benchmarking` | `198.18/15` |
| `multicast` | `224/4`, `ff00::/8` |
| `reserved` | `192.0.0/24`, `240/4` |
| `unique_local` | `fc00::/7` |
| `site_local` | `fec0::/10` |
| `discard` | `100::/64` |

The check is on the address roxy actually connects to, so DNS rebinding
does not get around it. It applies to IP addresses in URLs, `redirect`
targets and addon endpoints too.

An IPv4 address can be written as an IPv6 address in several ways, for
example `::ffff:10.0.0.1`, or through NAT64 (`64:ff9b::/96`) or 6to4
(`2002::/16`). Denies match all of these forms. `allow_cidrs` only matches
the plain form of an address, so it cannot be used to sneak a private
address through.

A refused connection gets `403` with `terminal_rule: _address_policy`, and
an `upstream_denied` event in the flow log names the address and the
range or list that matched.

## Address lists

Address lists are named sets of IP ranges. They can be used to refuse
connections (`upstream.deny_lists`) and in rules, as `@name`.

```yaml
address_lists:
  - name: blocked
    file: /etc/roxy/lists/blocked.txt    # one address or CIDR per line; `#` comments
  - name: cloud-metadata
    inline: [169.254.169.254/32, "fd00:ec2::254/128", 100.100.100.200/32]
```

- In rules, use `@name` after `in` or `not in` with an IP field:
  `client.ip in @internal`. In a rule, a list only matches the plain form
  of an address, since a rule may allow on it.
- Lists are fast to search: a million entries take about 11 MiB.
- A file larger than `limits.max_address_list_bytes` (256 MiB), or with a
  malformed line, fails to load.
- List files are watched and reloaded with the config.
- `roxy check` reports how many entries each list has. In
  `roxy rule test`, a list that fails to load makes every rule that reads
  it deny.
