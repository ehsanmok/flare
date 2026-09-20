# Autobahn WebSocket conformance

`autobahn.json` is the `wstest -m fuzzingclient` spec.
`tests/tools/run_conformance.sh` drives it: it builds
`examples/basic/websocket_echo_server.mojo`, starts it with an
unlimited connection budget on `WS_ECHO_PORT`, waits for the port,
runs the fuzzing client, and then gates the report against
`autobahn-known-fail.txt`.

Two things about the spec are deliberate.

**The `url` port must match `WS_ECHO_PORT` in the runner.** The spec
format has no way to read an environment variable, so the two are
kept in step by hand. Both are 19001.

**Cases 12.\* and 13.\* are excluded.** They are permessage-deflate.
flare implements the extension, in `flare.ws.permessage_deflate`,
fuzzed by `fuzz-ws-deflate` and `fuzz-pmd-context`, but the
standalone `WsServer` handshake does not negotiate it, so the echo
server would answer every one of those cases uncompressed. Running
them would report a failure about this fixture rather than about the
library. They come back when the handshake negotiates the extension.

The spec is kept free of comment keys because the fuzzing client
validates the document and an unknown key is a parse error, not a
warning.

## Running it

`wstest` ships in `autobahntestsuite`, which is Python 2 only. The
runner therefore falls back to the maintained Docker image, which is
what CI uses:

```bash
docker pull crossbario/autobahn-testsuite:latest
pixi run conformance autobahn
```

The HTML report lands in `target/conformance/autobahn/`.
