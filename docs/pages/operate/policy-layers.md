# Policy layers

`roxy policy render` composes a policy from layers. An organisation writes
one layer with its baseline allows and a ceiling; each proxy adds a layer
of its own; the per-node settings live in a base. The renderer writes one
`roxy.yaml` that `roxy check` accepts and `roxy run` loads like any other.

```sh
roxy policy render --base node.yaml --layer org.yaml --layer team.yaml -o roxy.yaml
roxy policy test   --base node.yaml --layer org.yaml --layer team.yaml
```

The first `--layer` is outermost: the organisation's. Each layer below it
is a lower layer. `render` runs every layer's tests against the result and
writes nothing if one fails. `test` runs the tests and writes nothing.

## Why concatenation is enough

Three properties of the rule engine make a stack of layers one list of
rules. A deny wins wherever it sits, so a higher layer's denies bound every
layer below: a lower layer can narrow the policy but never widen it. Rule
order orders effects, not decisions, so a layer's position only decides
whose `set_header` wins (the later one, as within a single file) and whose
tags it can read. And every name a layer defines gets the layer's name as
a prefix, so a lower layer cannot redefine, remove or reconfigure anything
a higher layer wrote. The renderer does not rewrite rules: each layer's
rules reach the output as written, apart from the prefixes.

## Layers

A layer is a YAML document with any of these keys, and no others:

| key | content |
|---|---|
| `name` | The layer's name; defaults to the file stem. Must match `[A-Za-z_][A-Za-z0-9_]*` and not contain `__`. |
| `rules` | As in the config file. |
| `metrics` | As in the config file. |
| `address_lists` | As in the config file. |
| `secrets` | A list of names: the secrets this layer's rules use. No sources. |
| `addons` | As in the config file. |
| `tests` | The layer's test suite, below. |

Listeners, `tls`, `limits`, `http`, `upstream`, `log` and `capture_dir`
are per-node and may not appear in a layer.

```yaml
name: org
metrics:
  - { id: github_writes, count: requests, where: 'host under "github.com" and method in [POST, PUT, PATCH, DELETE]', key: [client.ip], window: 1h }
secrets: [github_token]
rules:
  - id: ceiling
    when: not host under "github.com"
    then: deny
  - id: mark-writes
    when: method in [POST, PUT, PATCH, DELETE]
    then: { tag: write }
  - id: github
    when: host under "github.com"
    then:
      - set_header: { authorization: "Bearer ${secret:github_token}" }
      - allow
tests:
  - { name: outside github is denied, request: GET https://example.com/, expect: deny, rule: ceiling }
```

## The base

The base is a config file without `rules`, `metrics`, `address_lists` or
`addons`; the renderer refuses one that carries them. Its `secrets` map
gives the source of every secret the layers name, under the prefixed name,
and nothing else: where a value comes from (an environment variable on
this host, a file in this container) is per-node, which is why the layer
names the secret and the base supplies it.

```yaml
version: 1
listeners:
  - { name: proxy, bind: 0.0.0.0:3128 }
secrets:
  "org:github_token": { env: GITHUB_TOKEN }
```

## Names

Every name a layer defines is prefixed with the layer's name, and every
reference in the layer is rewritten to match, so a re-render with the same
inputs gives the same ids and metric series survive it.

| what | prefix | example |
|---|---|---|
| rule id | `<layer>:` | `org:ceiling` |
| addon name | `<layer>:` | `org:monitor` |
| secret | `<layer>:` | `${secret:org:github_token}` |
| metric id | `<layer>__` | `metric.org__github_writes` |
| address list | `<layer>__` | `@org__internal` |

Metric ids and list names are identifiers in the rule language, so their
separator is `__`. A layer's own names must not contain the separator.

A lower layer may read a higher layer's metrics and lists by their prefixed
name (`metric.org__github_writes`); the reverse is an error, as is a name
the layer in question does not define. A layer may only use the secrets it
names itself: a `${secret:org:...}` in another layer is refused, because a
`set_header` with the organisation's credential on a host the lower layer
chose would hand that credential over.

Tags are not prefixed. Addons set tags too, and a rule reads a tag by its
name wherever it was set. Instead the renderer checks direction: a rule may
read a tag set by its own layer or a layer above, never one set only by a
layer below. Such a read would always be false, since rules run top to
bottom, so the stack is refused with both rule ids rather than reordered.

## Addons

The output's `addons` are the layers' in stack order: the first layer's
addons first, in that layer's order, then the next layer's. A lower layer
can add addons below a higher layer's; it cannot remove, reorder or
reconfigure them, and an addon name containing `:` is refused.

## Tests

Each layer's `tests` are requests in `roxy rule test` form with the
decision the composed policy must reach. Names in a test are the layer's
own: `metrics` keys and `rule` are prefixed like the rules, and `rule` may
name a rule of a layer above by its prefixed id (`org:ceiling`).

| key | content |
|---|---|
| `name` | Shown in the report; defaults to `tests[i]`. |
| `request` | `METHOD URL`. |
| `headers`, `body`, `client_ip`, `state`, `tags` | As the `roxy rule test` flags of the same name. |
| `metrics` | `id: value`; a metric not given is 0. |
| `expect` | `allow` or `deny`. |
| `rule` | The rule expected to decide, if it matters. |

The tests run against the whole stack, with the dry run `roxy rule test`
uses. A failing `deny` test is an error: the composed policy lets through
something a layer meant to stop, so `render` exits 1 and writes nothing. A
failing `allow` test is a warning on stderr: a lower layer narrowed the
policy, which layers are entitled to do, and the layer's author should know
its allow is dead.

## Content hash

The output's first line is `# roxy policy render: inputs sha256:...`, a
hash of the base and the layers (names included) in a canonical form: key
order and quoting do not change it; content, layer order and layer names
do. `--print-hash` with `--output` prints it to stdout.

## What the renderer checks

The composed rules, metrics and addon conditions are compiled with the
same compiler `roxy check` uses, so a reference that does not resolve, a
duplicate id or an ill-typed expression is reported before anything is
written. The file-backed parts of `check` (loading address-list files,
compiling WASM addons) are left to the node, where those files are.
