# tcp_over_mqtt

A secure bidirectional TCP-over-MQTT tunnel with batching, AEAD encryption, and TCP, HTTP, TLS, and SOCKS5 forwarding support.

> This is a security-sensitive proxy/tunnelling program. Use it only on systems and networks you are authorized to operate. Prefer MQTTS, broker ACLs, `aead`, narrowly scoped host/port rules, and `denyPrivateNetworks: true` where appropriate.

> **Intended use:** This project is suitable for simple point-to-point private-network tunnelling. Because it encapsulates TCP streams in batched MQTT publishes and deliberately rate-limits those publishes, it has higher overhead and lower efficiency than purpose-built proxy protocols. It is not intended for high-speed or high-throughput network proxying. This trade-off can be practical for low-cost deployments that use a managed SaaS MQTT broker, provided its quotas, ACLs, message-size limits, and acceptable-use policy fit the workload.

## Configuration and run

Configuration uses strict JSONC rather than YAML. Start from the paired examples:

```bash
cp config/connector.example.jsonc connector.jsonc
cp config/server.example.jsonc server.jsonc
export TOM_MQTT_USERNAME='...'
export TOM_MQTT_PASSWORD='...'
export TOM_BATCH_KEY='base64:replace-with-a-high-entropy-secret'

bun run src/cli.ts --config connector.jsonc
bun run src/cli.ts --config server.jsonc
```

The example configurations use `TOM_MQTT_USERNAME`, `TOM_MQTT_PASSWORD`, and
`TOM_BATCH_KEY`. All environment-variable names configured through
`usernameEnv`, `passwordEnv`, or `keyEnv` must begin with `TOM_`.

Batch publishing is deliberately throttled to protect the MQTT broker. The
defaults wait up to `batch.maxDelayMs=50` ms to collect records and enforce
`batch.minPublishIntervalMs=5` ms between MQTT publishes (at most about 200
publishes/second per node). They also reject new records when the
outbound queue reaches `batch.maxQueuedRecords=4096`, rather than allowing
unbounded memory growth. Increasing either publish rate should be
done only after confirming the broker's limits and monitoring its queue.

Secrets are resolved with **environment-first precedence**. If the configured
environment variable exists, its value is used. If it is absent, the program
uses the corresponding configuration fallback: `mqtt.username`,
`mqtt.password`, or `batch.key`. If an `*Env` field is configured but neither
source supplies a value, startup fails. An environment variable set to an empty
string is still considered present and overrides the fallback; an empty AEAD or
RC4 key is subsequently rejected.

Example with fallbacks:

```jsonc
"mqtt": {
  "username": "fallback-user",
  "password": "fallback-password",
  "usernameEnv": "TOM_MQTT_USERNAME",
  "passwordEnv": "TOM_MQTT_PASSWORD"
},
"batch": {
  "protection": "aead",
  "key": "base64:fallback-key-material",
  "keyEnv": "TOM_BATCH_KEY"
}
```

Configuration fallbacks are plain text in the JSONC file. Restrict file
permissions and do not commit real credentials. `batch.key` and
`TOM_BATCH_KEY` accept raw text, `base64:<value>`, or `hex:<value>`. `aead`
derives an AES-256-GCM key with SHA-256 and authenticates the entire MQTT topic
as AAD. `rc4` is intentionally retained only for compatibility and **does not
authenticate data**.

Every `protocols` switch (`tcp`, `tls`, `http`, `socks`) must be explicit. When an enabled policy exposes `allowedHosts`/`allowedPorts`, both arrays must be present. `[]` means unrestricted for that dimension; omitting the field is a startup error. The generic `egress` arrays are also explicit.

## Build a standalone executable

Use the included build script to compile the application and its runtime dependencies into one executable for the current platform:

```bash
bun run build
```

The output is written to:

```text
dist/tcp_over_mqtt
```

Run it with an external JSONC configuration and environment-provided secrets:

```bash
export TOM_MQTT_USERNAME='...'
export TOM_MQTT_PASSWORD='...'
export TOM_BATCH_KEY='base64:replace-with-a-high-entropy-secret'

./dist/tcp_over_mqtt --config connector.jsonc
```

The resulting executable does not require Bun or `node_modules` on the target machine. The build script deliberately disables automatic `.env` and `bunfig.toml` loading for the standalone executable; provide credentials through the service environment or a secret manager.

Cross-compilation scripts are also available:

```bash
bun run build:linux-x64
bun run build:linux-arm64
bun run build:windows-x64
```

They produce:

```text
dist/tcp_over_mqtt-linux-x64
dist/tcp_over_mqtt-linux-arm64
dist/tcp_over_mqtt-windows-x64.exe
```

Cross-compilation may download the matching Bun runtime. Clean all build output with:

```bash
bun run clean
```

Do not embed MQTT credentials or encryption keys into an executable. The `dist/` directory is ignored by Git.

## Topic format

```text
{topicPrefix}/{direction}/{toNodeId}/{fromNodeId}/{archive}/{protection}/batch
```

Example:

```text
$tenant/acme/prod/c2s/server-a/connector-a/tgz/aead/batch
```

- `direction`: `c2s` or `s2c`.
- `toNodeId`: MQTT receiver; subscription is `{topicPrefix}/+/{nodeId}/+/+/+/batch`.
- `fromNodeId`: sender node; should be constrained by broker ACL.
- `archive`: `tar` or `tgz`.
- `protection`: `plain`, `aead` (AES-256-GCM) or compatibility-only `rc4`.

`topicPrefix` may contain up to eight levels. A custom first level beginning with `$` is valid (for example `$tenant`), but broker-reserved roots such as `$SYS`, `$share`, `$queue`, `$bridge`, `$local`, `$delayed`, `$forward`, `$exclusive`, and `$CONTROL` are rejected.

All traffic under one configured node profile must use the configured `batch.archive` and `batch.protection`; receiving a different profile is rejected to prevent configuration drift/downgrade.

## Batch format

One MQTT message contains exactly one complete independent TAR/TAR.GZ archive; a TAR/gzip stream never crosses MQTT messages. The wire order is:

```text
TAR → optional gzip → protection → MQTT payload
```

Entries begin with `tom/v1/`. Metadata is UTF-8 text; `data` is byte-for-byte TCP payload:

```text
tom/v1/batch/id
tom/v1/batch/record-count
tom/v1/records/000001/tunnel-id
tom/v1/records/000001/sequence
tom/v1/records/000001/type
tom/v1/records/000001/protocol
tom/v1/records/000001/endpoint
tom/v1/records/000001/data
```

Other optional per-record files are `flags`, `error-code`, `error-message`, and `window-bytes`. Record types are `OPEN`, `OPEN_OK`, `OPEN_ERROR`, `DATA`, `FIN`, `CLOSE`, `CANCEL`, `WINDOW_UPDATE`, `ERROR`, `PING`, and `PONG`.

## Tunnel types

| Type | Meaning |
| --- | --- |
| `tcp` | Raw stream, no application hostname inspection. |
| `tls` | Raw TLS/legacy SSL passthrough; parses ClientHello SNI and ECH presence for policy. |
| `http` | Raw HTTP/1.x stream over the TCP tunnel; only the first request Host/port is parsed for policy. Paths, query, headers and body remain inside the original bytes. |
| `socks` | A local SOCKS5 **CONNECT** listener. The peer performs the actual dynamic outbound connection. SOCKS4, BIND and UDP ASSOCIATE are not implemented. |

> **HTTP forwarding notice:** the current `http` mode still performs raw TCP
> forwarding. It does not rewrite the request URL, `Host` header, hostname, or
> port. Ensure the origin server selected by `targetHost`/`targetPort` is
> configured to serve the same hostname used by the client. Using the same
> client-facing and origin port is recommended; if the ports differ, configure
> the origin virtual host and redirects so that the unchanged client request is
> still accepted.

An existing external SOCKS proxy is simply a fixed `tcp` target. `https` and `wss` use `tls`; they are not terminated or decrypted.

## Verify

```bash
bun run verify
```

The unit suite covers topic restrictions, strict config semantics, TAR/TGZ + protection round trips, batching, HTTP/TLS/SOCKS first-flight parsers, and access policy helpers. A live broker integration test is intentionally not bundled; validate against a broker with production ACLs before deployment.

## License

Licensed under the [Apache License 2.0](LICENSE).
