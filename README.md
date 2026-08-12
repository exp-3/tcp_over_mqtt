# tcp_over_mqtt

`tcp_over_mqtt` is a Bun + TypeScript implementation of a bidirectional TCP tunnel whose MQTT `PUBLISH` payloads carry independent TAR/TAR.GZ batches. TAR entries use the **`tom/v1/`** protocol prefix.

> This is a security-sensitive proxy/tunnelling program. Use it only on systems and networks you are authorized to operate. Prefer MQTTS, broker ACLs, `aead`, narrowly scoped host/port rules, and `denyPrivateNetworks: true` where appropriate.

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
| `http` | Raw HTTP/1.x stream; only first request Host/port is parsed for policy. Paths, query, headers and body remain inside raw bytes. |
| `socks` | A local SOCKS5 **CONNECT** listener. The peer performs the actual dynamic outbound connection. SOCKS4, BIND and UDP ASSOCIATE are not implemented. |

An existing external SOCKS proxy is simply a fixed `tcp` target. `https` and `wss` use `tls`; they are not terminated or decrypted.

## Configuration and run

Configuration uses strict JSONC rather than YAML. Start from the paired examples:

```bash
cp config/connector.example.jsonc connector.jsonc
cp config/server.example.jsonc server.jsonc
export MQTT_USERNAME='...'
export MQTT_PASSWORD='...'
export TOM_BATCH_KEY='base64:replace-with-a-high-entropy-secret'

bun run src/cli.ts --config connector.jsonc
bun run src/cli.ts --config server.jsonc
```

`TOM_BATCH_KEY` accepts raw text, `base64:<value>`, or `hex:<value>`. `aead` derives an AES-256-GCM key with SHA-256 and authenticates the entire MQTT topic as AAD. `rc4` is intentionally retained only for compatibility and **does not authenticate data**.

Every `protocols` switch (`tcp`, `tls`, `http`, `socks`) must be explicit. When an enabled policy exposes `allowedHosts`/`allowedPorts`, both arrays must be present. `[]` means unrestricted for that dimension; omitting the field is a startup error. The generic `egress` arrays are also explicit.

## Verify

```bash
bun run check
bun test
```

The unit suite covers topic restrictions, strict config semantics, TAR/TGZ + protection round trips, batching, HTTP/TLS/SOCKS first-flight parsers, and access policy helpers. A live broker integration test is intentionally not bundled; validate against a broker with production ACLs before deployment.

