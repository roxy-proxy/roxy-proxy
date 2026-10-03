"""The smallest useful service layer: stream every exchange through
unchanged, adding a request header and logging each exchange.

    pip install websockets
    python passthrough.py            # listens on 127.0.0.1:9000

and in roxy.yaml:

    addons:
      - name: passthrough
        kind: service
        endpoint: svc
        endpoints:
          svc: { url: "http://127.0.0.1:9000/", private_ok: true }
"""

import asyncio
import logging

from roxy_layer import Exchange, serve

log = logging.getLogger("passthrough")


async def handle(ex: Exchange) -> None:
    req = ex.request
    req.headers.append(("x-seen-by", "passthrough"))
    # Both bodies stream: each chunk goes on as soon as it arrives.
    res = await ex.forward(req, ex.body())
    log.info(
        "%s %s -> %d (flow %s)", req.method, req.url, res.status, ex.flow.get("roxy-flow-id")
    )
    await ex.respond(res, ex.response_body())


async def main() -> None:
    async with serve(handle, "127.0.0.1", 9000) as server:
        await server.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
