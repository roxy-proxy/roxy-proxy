# Address floor and lists

Rules decide by name; the address floor decides by IP, checking every
resolved address before roxy connects. Private ranges are denied by
default; address lists add ranges. Config: `upstream` and `address_lists`
([upstream](/reference/upstream)).

## Address floor

Checked in order per candidate IP; the first hit is the reason:

1. `deny_cidrs`: never valid, nothing opts out.
2. With `deny_private_ranges` (default true): the ranges below, except
   addresses in `allow_cidrs` and flows whose allow rule says
   `private_ok: true`.
3. Every list in `deny_lists`: never valid, nothing opts out.

| class (`private_range:<class>`) | ranges |
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

Denies match every form of an address: as given, IPv4-mapped,
IPv4-compatible, and the IPv4 address a NAT64 or 6to4 gateway would
translate it to (`64:ff9b::/96`, the local-use `64:ff9b:1::/48` with the
IPv4 address in the last 32 bits, `2002::/16`). `deny_cidrs:
[203.0.113.0/24]` also denies `64:ff9b::cb00:7107`; a NAT64 address
embedding a private IPv4 address is private. `allow_cidrs` matches narrowly:
the address in canonical form only, so an IPv4-mapped or IPv4-compatible
address (`::ffff:a.b.c.d`, `::a.b.c.d`) matches an IPv4 entry and nothing
else, and a translated form never matches.

The check is on the resolved IP, not the name, so DNS rebinding does not
help; IP-literal hosts pass the same check. If any resolved address is
denied the flow is: `403`, `terminal_rule: _address_policy`, `reason: address_policy`,
and an `upstream_denied` event with `host`, `port`, `resolved_ip`, `reason`
(`private_range:<class>`, `deny_cidrs` or `list:<name>`), `list` and
`matched_cidr`. `redirect` targets and addon endpoint calls pass the same
floor.

## Address lists

Named CIDR sets, used as an unconditional deny floor (`upstream.deny_lists`)
and as `@name` in rules.

```yaml
address_lists:
  - name: blocked
    file: /etc/roxy/lists/blocked.txt    # one IPv4/IPv6 CIDR or address per line; `#` comments
  - name: cloud-metadata
    inline: [169.254.169.254/32, "fd00:ec2::254/128", 100.100.100.200/32]
```

- **Representation.** Two sorted tables of disjoint CIDR blocks per list,
  one per family, binary-searched: 8 bytes per IPv4 block, 32 per IPv6, no
  allocation per lookup (a million IPv4 plus 100k IPv6 entries: about
  11 MiB, tens of nanoseconds). Nested and duplicate entries merge. A
  malformed line is an error naming file and line; a malformed inline entry
  is reported at `address_lists[i].inline[j]`. A file over
  `limits.max_address_list_bytes` (256 MiB), or not valid UTF-8, is a load
  error.
- **Matching.** The deny floor matches every form
  ([above](/reference/address-lists#address-floor)), since matching more
  is the safe direction for a deny. Rule membership (`ip
  in @list`) is exact, with only the IPv4-mapped equivalence, since a rule
  may *allow* on it: `client.ip in @internal` must not treat a 6to4 address
  embedding an internal IPv4 address as internal.
- **In rules.** `@name` works wherever a CIDR does: right of `in` / `not
  in` with an ip field. An undefined list is a compile error.
- **Reload.** List files are watched with the config. A changed file is
  recompiled and swapped with the policy, and upstream pools are flushed,
  so a pooled connection to a newly denied IP is never reused. An exchange
  in flight keeps its policy, pools and lists, and can still open a
  connection the new lists would deny; the next exchange on the connection
  uses the new lists.
- `roxy check` reports each list's entry count. `roxy rule test` loads
  lists as `roxy run` would; if one fails to load it warns and treats every
  `@list` as unavailable, so a rule reading one fails closed.
