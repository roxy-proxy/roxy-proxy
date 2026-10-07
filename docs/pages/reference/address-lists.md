# Address floor and lists

Rules decide by name. The address floor decides by IP: after roxy resolves
a name, and before it connects, every address is checked. Private ranges
are denied by default, and address lists add ranges you name. The config
for both is under `upstream` and `address_lists`
([upstream](/reference/upstream)).

## Address floor

After resolution and before every connect, each candidate IP is checked, in
this order; the first hit is the reason reported:

1. `deny_cidrs`: never valid, and nothing opts out.
2. With `deny_private_ranges` (default true): the private and special
   ranges below are denied, except addresses in `allow_cidrs` and flows
   whose allow rule says `private_ok: true`.
3. Every list in `deny_lists`: never valid, and nothing opts out.

The private floor denies these ranges, each reported as
`private_range:<class>`:

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

Denies match every form of an address that a connection to it may reach:
the address as given, its IPv4-mapped and IPv4-compatible forms, and the
IPv4 address a NAT64 or 6to4 gateway would translate it to (`64:ff9b::/96`,
the local-use `64:ff9b:1::/48` with the IPv4 address in the last 32 bits,
and `2002::/16`). So `deny_cidrs: [203.0.113.0/24]` also denies
`64:ff9b::cb00:7107`, and a NAT64 address that embeds a private IPv4
address is a private address. `allow_cidrs` is an exemption and matches
narrowly: the address itself and its IPv4 form (IPv4-mapped `::ffff:a.b.c.d`
or IPv4-compatible `::a.b.c.d`), never a translated form.

The check is on the resolved IP, not the name, so DNS rebinding does not
help, and IP-literal hosts go through the same check. If any resolved
address is denied, the whole flow is denied: an attacker-controlled name
does not get a second roll of the dice. A hit denies with `403`,
`terminal_rule: _address_policy`, `reason: address_policy`, and an
`upstream_denied` event naming the `host` and `port`, the `resolved_ip`, the
`reason` (`private_range:<class>`, `deny_cidrs` or `list:<name>`), the
`list` that matched and the `matched_cidr`.

`redirect` targets and addon endpoint calls pass the same floor.

## Address lists

Named sets of CIDR ranges (threat-intel feeds, cloud metadata ranges, whole
countries), used as an unconditional deny floor and as `@name` in rules.

```yaml
address_lists:
  - name: blocked
    file: /etc/roxy/lists/blocked.txt    # one IPv4/IPv6 CIDR or address per line; `#` comments
  - name: cloud-metadata
    inline: [169.254.169.254/32, "fd00:ec2::254/128", 100.100.100.200/32]
```

- **Representation.** Each list compiles into two sorted tables of disjoint
  CIDR blocks, one per family, looked up by binary search: 8 bytes per IPv4
  block, 32 per IPv6, no allocation per lookup. A million IPv4 plus 100k
  IPv6 entries take about 11 MiB and look up in tens of nanoseconds.
  Nested and duplicate entries are merged; a malformed line is an error
  naming the file and line, and a malformed inline entry is reported at
  `address_lists[i].inline[j]`. A file larger than
  `limits.max_address_list_bytes` (256 MiB), or one that is not valid
  UTF-8, is a load error.
- **Two matching modes.** The deny floor matches broadly, every form
  [above](/reference/address-lists#address-floor), because matching more is the safe direction for
  a deny. Rule membership
  (`ip in @list`) is exact, with only the IPv4-mapped equivalence, because a
  rule might *allow* on membership: `client.ip in @internal` must not treat
  a 6to4 address embedding an internal IPv4 address as internal.
- **In rules.** `@name` works wherever a CIDR does, on the right of `in` /
  `not in` with an ip field: `client.ip in @internal`. An undefined list is
  a compile error.
- **Reload.** List files are watched with the config. A changed file is
  recompiled and swapped with the policy, and the upstream connection pools
  are flushed, so a pooled connection to a newly denied IP is never reused.
  An exchange already in flight keeps the policy it started under until it
  ends, including its pools and lists, so it can still open a connection
  the new lists would deny. The window is that one exchange; the next one
  on the connection uses the new lists.
- `roxy check` reports the entry count of each list. `roxy rule test` loads
  the lists as `roxy run` would; if any fails to load it warns and treats
  every `@list` as unavailable, so a rule reading one fails closed.
