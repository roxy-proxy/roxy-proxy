# Service layers in Python

A service layer is an external service in roxy's network path
([docs/addons.md](../../../docs/addons.md#service-layers)): each exchange streams through it over a WebSocket
(`roxy.layer.v1`), request and response, and it can pass either on,
change it, hold it back, answer itself or refuse. Whatever it forwards is
still checked like a client request and judged by roxy's rules, and if it
fails, the exchange fails closed.

| file | what it is |
|---|---|
| [`roxy_layer.py`](roxy_layer.py) | The service side of `roxy.layer.v1` for asyncio: one coroutine per exchange. Needs only `websockets`. |
| [`passthrough.py`](passthrough.py) | The smallest layer: streams everything through, adds a header, logs. |
| [`sentinel/`](sentinel) | [inspect_sentinel](https://github.com/meridianlabs-ai/inspect_sentinel) monitors and protocols judging model API traffic. |

## The handler

```python
from roxy_layer import Exchange, serve

async def handle(ex: Exchange) -> None:
    # ex.request: method, absolute url, headers; ex.flow: roxy-flow-* metadata
    response = await ex.forward(ex.request, ex.body())     # on down the stack
    await ex.respond(response, ex.response_body())          # back to the client
```

- `ex.body()` / `ex.response_body()` stream the bodies; `read_body()` /
  `read_response_body()` read them whole.
- `forward(request, body)` sends a request on (the WASM SDK's `next`):
  roxy re-validates it, the rules judge it, and the response from below
  comes back. `body` is bytes or an async iterable of bytes.
- `respond(response, body)` gives the client a response: after `forward`,
  in place of the one from below; before it, instead of forwarding at all.
- `deny(status, message)` refuses, before or after forwarding.
- Heads carry `content-length` when the length is known. If you change a
  body's length, fix or drop it: roxy holds a body to its declared length.
- In `mode: observe` (`ex.observing`), roxy sends copies and ignores what
  the layer sends back.

If the handler raises, the socket closes without an answer, and roxy
fails the exchange closed: a `503` (`layer:<name>`) before the response
head, a cut body after it.

## Running one

```sh
pip install websockets
python passthrough.py               # 127.0.0.1:9000
```

```yaml
addons:
  - name: passthrough
    kind: service
    endpoint: svc
    endpoints:
      svc: { url: "http://127.0.0.1:9000/", private_ok: true }
    limits: { first_byte_timeout: 5s, max_exchange_time: 120s }
```
