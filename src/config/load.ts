import { parse as parseJsonc, printParseErrorCode, type ParseError } from "jsonc-parser";
import type {
  AccessConfig,
  AppConfig,
  BatchConfig,
  HttpConfig,
  ListenerConfig,
  MqttConfig,
  ProtocolSwitches,
  SocksConfig,
  TlsConfig,
  TunnelConfig,
  TunnelProtocol,
  HttpOriginProtocol,
} from "../types.ts";
import { PROTOCOLS } from "../types.ts";
import {
  assertNoUnknownKeys,
  assertObject,
  booleanValue,
  integerValue,
  numberArray,
  optionalString,
  requiredString,
  stringArray,
} from "../util/assert.ts";
import { validateNodeId, validateTopicPrefix } from "../protocol/topic.ts";

export async function loadConfig(path: string): Promise<AppConfig> {
  const text = await Bun.file(path).text();
  let raw: unknown;
  try {
    const errors: ParseError[] = [];
    raw = parseJsonc(text, errors, { allowTrailingComma: false, disallowComments: false });
    if (errors.length > 0) {
      const first = errors[0]!;
      throw new Error(`cannot parse JSONC configuration '${path}' at offset ${first.offset}: ${printParseErrorCode(first.error)}`);
    }
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("cannot parse JSONC configuration")) throw error;
    throw new Error(`cannot parse JSONC configuration '${path}': ${String(error)}`);
  }
  return parseConfig(raw);
}

export function parseConfig(raw: unknown): AppConfig {
  assertObject(raw, "config");
  assertNoUnknownKeys(
    raw,
    ["role", "nodeId", "mqtt", "protocols", "batch", "tunnel", "egress", "http", "tls", "socks", "listeners"],
    "config",
  );

  const role = requiredString(raw.role, "role");
  if (role !== "connector" && role !== "server") throw new Error("role must be 'connector' or 'server'");
  const nodeId = validateNodeId(requiredString(raw.nodeId, "nodeId"));
  const protocols = parseProtocols(raw.protocols);

  return {
    role,
    nodeId,
    mqtt: parseMqtt(raw.mqtt, nodeId),
    protocols,
    batch: parseBatch(raw.batch),
    tunnel: parseTunnel(raw.tunnel),
    egress: parseAccess(raw.egress, "egress", true),
    http: parseHttp(raw.http, protocols.http),
    tls: parseTls(raw.tls, protocols.tls),
    socks: parseSocks(raw.socks, protocols.socks),
    listeners: parseListeners(raw.listeners, protocols),
  };
}

function parseMqtt(raw: unknown, nodeId: string): MqttConfig {
  assertObject(raw, "mqtt");
  assertNoUnknownKeys(raw, ["url", "clientId", "topicPrefix", "protocolVersion", "qos", "username", "password", "usernameEnv", "passwordEnv", "rejectUnauthorized"], "mqtt");
  const protocolVersion = integerValue(raw.protocolVersion, "mqtt.protocolVersion", { min: 4, max: 5, fallback: 5 });
  if (protocolVersion !== 4 && protocolVersion !== 5) throw new Error("mqtt.protocolVersion must be 4 or 5");
  const qos = integerValue(raw.qos, "mqtt.qos", { min: 0, max: 2, fallback: 1 });
  const username = optionalString(raw.username, "mqtt.username");
  const password = optionalString(raw.password, "mqtt.password");
  const usernameEnv = parseTomEnvName(raw.usernameEnv, "mqtt.usernameEnv");
  const passwordEnv = parseTomEnvName(raw.passwordEnv, "mqtt.passwordEnv");
  return {
    url: requiredString(raw.url, "mqtt.url"),
    clientId: raw.clientId === undefined ? nodeId : requiredString(raw.clientId, "mqtt.clientId"),
    topicPrefix: validateTopicPrefix(requiredString(raw.topicPrefix, "mqtt.topicPrefix")),
    protocolVersion,
    qos: qos as 0 | 1 | 2,
    ...(username !== undefined ? { username } : {}),
    ...(password !== undefined ? { password } : {}),
    ...(usernameEnv ? { usernameEnv } : {}),
    ...(passwordEnv ? { passwordEnv } : {}),
    rejectUnauthorized: booleanValue(raw.rejectUnauthorized, "mqtt.rejectUnauthorized", true),
  };
}

function parseProtocols(raw: unknown): ProtocolSwitches {
  assertObject(raw, "protocols");
  assertNoUnknownKeys(raw, PROTOCOLS, "protocols");
  return {
    tcp: booleanValue(raw.tcp, "protocols.tcp"),
    tls: booleanValue(raw.tls, "protocols.tls"),
    http: booleanValue(raw.http, "protocols.http"),
    socks: booleanValue(raw.socks, "protocols.socks"),
  };
}

function parseBatch(raw: unknown): BatchConfig {
  assertObject(raw, "batch");
  assertNoUnknownKeys(raw, ["archive", "protection", "maxBatchBytes", "maxRecordsPerBatch", "maxDelayMs", "minPublishIntervalMs", "maxQueuedRecords", "maxDecompressedBytes", "maxCompressionRatio", "key", "keyEnv"], "batch");
  const archive = requiredString(raw.archive, "batch.archive");
  const protection = requiredString(raw.protection, "batch.protection");
  if (archive !== "tar" && archive !== "tgz") throw new Error("batch.archive must be 'tar' or 'tgz'");
  if (protection !== "plain" && protection !== "aead" && protection !== "rc4") {
    throw new Error("batch.protection must be 'plain', 'aead', or 'rc4'");
  }
  const key = optionalString(raw.key, "batch.key");
  const keyEnv = parseTomEnvName(raw.keyEnv, "batch.keyEnv");
  if (protection !== "plain" && !keyEnv && key === undefined) {
    throw new Error("batch.keyEnv or batch.key is required for aead or rc4 protection");
  }
  return {
    archive,
    protection,
    maxBatchBytes: integerValue(raw.maxBatchBytes, "batch.maxBatchBytes", { min: 12_288, max: 16_777_216, fallback: 48_000 }),
    maxRecordsPerBatch: integerValue(raw.maxRecordsPerBatch, "batch.maxRecordsPerBatch", { min: 1, max: 4096, fallback: 64 }),
    maxDelayMs: integerValue(raw.maxDelayMs, "batch.maxDelayMs", { min: 1, max: 60_000, fallback: 50 }),
    minPublishIntervalMs: integerValue(raw.minPublishIntervalMs, "batch.minPublishIntervalMs", { min: 0, max: 60_000, fallback: 5 }),
    maxQueuedRecords: integerValue(raw.maxQueuedRecords, "batch.maxQueuedRecords", { min: 1, max: 1_000_000, fallback: 4096 }),
    maxDecompressedBytes: integerValue(raw.maxDecompressedBytes, "batch.maxDecompressedBytes", { min: 4096, max: 268_435_456, fallback: 8_388_608 }),
    maxCompressionRatio: integerValue(raw.maxCompressionRatio, "batch.maxCompressionRatio", { min: 1, max: 10_000, fallback: 100 }),
    ...(key !== undefined ? { key } : {}),
    ...(keyEnv ? { keyEnv } : {}),
  };
}

function parseTomEnvName(value: unknown, path: string): string | undefined {
  const name = optionalString(value, path);
  if (name !== undefined && !name.startsWith("TOM_")) {
    throw new Error(`${path} must start with 'TOM_'`);
  }
  return name;
}

function parseTunnel(raw: unknown): TunnelConfig {
  assertObject(raw, "tunnel");
  assertNoUnknownKeys(raw, ["maxConcurrentTunnels", "maxBufferedBytesPerTunnel", "idleTimeoutMs", "connectTimeoutMs"], "tunnel");
  return {
    maxConcurrentTunnels: integerValue(raw.maxConcurrentTunnels, "tunnel.maxConcurrentTunnels", { min: 1, max: 1_000_000, fallback: 1024 }),
    maxBufferedBytesPerTunnel: integerValue(raw.maxBufferedBytesPerTunnel, "tunnel.maxBufferedBytesPerTunnel", { min: 4096, max: 268_435_456, fallback: 1_048_576 }),
    idleTimeoutMs: integerValue(raw.idleTimeoutMs, "tunnel.idleTimeoutMs", { min: 1000, max: 86_400_000, fallback: 60_000 }),
    connectTimeoutMs: integerValue(raw.connectTimeoutMs, "tunnel.connectTimeoutMs", { min: 100, max: 300_000, fallback: 10_000 }),
  };
}

function parseAccess(raw: unknown, path: string, requiredArrays: boolean): AccessConfig {
  assertObject(raw, path);
  assertNoUnknownKeys(raw, ["allowedHosts", "allowedPorts", "denyPrivateNetworks"], path);
  return {
    allowedHosts: stringArray(raw.allowedHosts, `${path}.allowedHosts`, requiredArrays),
    allowedPorts: numberArray(raw.allowedPorts, `${path}.allowedPorts`, requiredArrays),
    denyPrivateNetworks: booleanValue(raw.denyPrivateNetworks, `${path}.denyPrivateNetworks`, false),
  };
}

function parseHttp(raw: unknown, enabled: boolean): HttpConfig {
  assertObject(raw, "http");
  assertNoUnknownKeys(raw, ["allowedHosts", "allowedPorts", "denyPrivateNetworks", "requestHeaderMaxBytes", "requestHeaderTimeoutMs", "responseHeaderMaxBytes", "responseHeaderTimeoutMs"], "http");
  const access = {
    allowedHosts: stringArray(raw.allowedHosts, "http.allowedHosts", enabled),
    allowedPorts: numberArray(raw.allowedPorts, "http.allowedPorts", enabled),
    denyPrivateNetworks: booleanValue(raw.denyPrivateNetworks, "http.denyPrivateNetworks", false),
  };
  return {
    ...access,
    requestHeaderMaxBytes: integerValue(raw.requestHeaderMaxBytes, "http.requestHeaderMaxBytes", { min: 1024, max: 1_048_576, fallback: 65_536 }),
    requestHeaderTimeoutMs: integerValue(raw.requestHeaderTimeoutMs, "http.requestHeaderTimeoutMs", { min: 100, max: 300_000, fallback: 5_000 }),
    responseHeaderMaxBytes: integerValue(raw.responseHeaderMaxBytes, "http.responseHeaderMaxBytes", { min: 1024, max: 1_048_576, fallback: 65_536 }),
    responseHeaderTimeoutMs: integerValue(raw.responseHeaderTimeoutMs, "http.responseHeaderTimeoutMs", { min: 100, max: 300_000, fallback: 5_000 }),
  };
}

function parseTls(raw: unknown, enabled: boolean): TlsConfig {
  assertObject(raw, "tls");
  assertNoUnknownKeys(raw, ["allowedHosts", "allowedPorts", "denyPrivateNetworks", "requireSni", "requireEndpointSniMatch", "allowEch", "allowedEchPublicNames", "legacySsl", "clientHelloMaxBytes", "clientHelloTimeoutMs"], "tls");
  const legacySsl = raw.legacySsl === undefined ? "reject" : requiredString(raw.legacySsl, "tls.legacySsl");
  if (legacySsl !== "reject" && legacySsl !== "static-route-only") {
    throw new Error("tls.legacySsl must be 'reject' or 'static-route-only'");
  }
  return {
    allowedHosts: stringArray(raw.allowedHosts, "tls.allowedHosts", enabled),
    allowedPorts: numberArray(raw.allowedPorts, "tls.allowedPorts", enabled),
    denyPrivateNetworks: booleanValue(raw.denyPrivateNetworks, "tls.denyPrivateNetworks", false),
    requireSni: booleanValue(raw.requireSni, "tls.requireSni", true),
    requireEndpointSniMatch: booleanValue(raw.requireEndpointSniMatch, "tls.requireEndpointSniMatch", true),
    allowEch: booleanValue(raw.allowEch, "tls.allowEch", false),
    allowedEchPublicNames: stringArray(raw.allowedEchPublicNames, "tls.allowedEchPublicNames"),
    legacySsl,
    clientHelloMaxBytes: integerValue(raw.clientHelloMaxBytes, "tls.clientHelloMaxBytes", { min: 1024, max: 1_048_576, fallback: 65_536 }),
    clientHelloTimeoutMs: integerValue(raw.clientHelloTimeoutMs, "tls.clientHelloTimeoutMs", { min: 100, max: 300_000, fallback: 5_000 }),
  };
}

function parseSocks(raw: unknown, enabled: boolean): SocksConfig {
  assertObject(raw, "socks");
  assertNoUnknownKeys(raw, ["allowedHosts", "allowedPorts", "denyPrivateNetworks", "connectTimeoutMs"], "socks");
  return {
    allowedHosts: stringArray(raw.allowedHosts, "socks.allowedHosts", enabled),
    allowedPorts: numberArray(raw.allowedPorts, "socks.allowedPorts", enabled),
    denyPrivateNetworks: booleanValue(raw.denyPrivateNetworks, "socks.denyPrivateNetworks", false),
    connectTimeoutMs: integerValue(raw.connectTimeoutMs, "socks.connectTimeoutMs", { min: 100, max: 300_000, fallback: 10_000 }),
  };
}

function parseListeners(raw: unknown, protocols: ProtocolSwitches): ListenerConfig[] {
  if (!Array.isArray(raw)) throw new Error("listeners must be an array");
  const names = new Set<string>();
  const addresses = new Set<string>();
  return raw.map((value, index) => {
    const path = `listeners[${index}]`;
    assertObject(value, path);
    assertNoUnknownKeys(value, ["name", "type", "listenHost", "listenPort", "toNodeId", "targetHost", "targetPort", "originHost", "originPort", "originProtocol", "originRequestHost"], path);
    const name = requiredString(value.name, `${path}.name`);
    if (names.has(name)) throw new Error(`duplicate listener name '${name}'`);
    names.add(name);
    const type = requiredString(value.type, `${path}.type`) as TunnelProtocol;
    if (!PROTOCOLS.includes(type)) throw new Error(`${path}.type is unsupported`);
    if (!protocols[type]) throw new Error(`${path} uses globally disabled protocol '${type}'`);
    const listenHost = requiredString(value.listenHost, `${path}.listenHost`);
    const listenPort = integerValue(value.listenPort, `${path}.listenPort`, { min: 1, max: 65535 });
    const address = `${listenHost}:${listenPort}`;
    if (addresses.has(address)) throw new Error(`duplicate listener address '${address}'`);
    addresses.add(address);
    const toNodeId = validateNodeId(requiredString(value.toNodeId, `${path}.toNodeId`), `${path}.toNodeId`);

    if (type === "http") {
      if (value.targetHost !== undefined || value.targetPort !== undefined) {
        throw new Error(`${path} HTTP listener uses originHost/originPort instead of targetHost/targetPort`);
      }
      const originHost = requiredString(value.originHost, `${path}.originHost`);
      const originPort = integerValue(value.originPort, `${path}.originPort`, { min: 1, max: 65535 });
      const originProtocol = requiredString(value.originProtocol, `${path}.originProtocol`) as HttpOriginProtocol;
      if (originProtocol !== "http" && originProtocol !== "https") throw new Error(`${path}.originProtocol must be 'http' or 'https'`);
      const originRequestHost = optionalString(value.originRequestHost, `${path}.originRequestHost`);
      if (originRequestHost !== undefined) validateHttpAuthority(originRequestHost, `${path}.originRequestHost`);
      return { name, type, listenHost, listenPort, toNodeId, originHost, originPort, originProtocol, ...(originRequestHost !== undefined ? { originRequestHost } : {}) };
    }

    if (value.originHost !== undefined || value.originPort !== undefined || value.originProtocol !== undefined || value.originRequestHost !== undefined) {
      throw new Error(`${path} only HTTP listeners may set originHost/originPort/originProtocol/originRequestHost`);
    }
    if (type === "socks") {
      if (value.targetHost !== undefined || value.targetPort !== undefined) throw new Error(`${path} SOCKS listener must not set targetHost or targetPort`);
      return { name, type, listenHost, listenPort, toNodeId };
    }
    const targetHost = requiredString(value.targetHost, `${path}.targetHost`);
    const targetPort = integerValue(value.targetPort, `${path}.targetPort`, { min: 1, max: 65535 });
    return { name, type, listenHost, listenPort, toNodeId, targetHost, targetPort };
  });
}

function validateHttpAuthority(value: string, path: string): void {
  if (value.length === 0 || value.length > 512 || /[\s\u0000-\u001f\u007f\/\?#@]/u.test(value)) {
    throw new Error(`${path} must be a valid HTTP Host authority`);
  }
  if (value.startsWith("[")) {
    if (!/^\[[0-9A-Fa-f:.]+\](?::[1-9][0-9]{0,4})?$/.test(value)) throw new Error(`${path} must be a valid bracketed IPv6 HTTP Host authority`);
    return;
  }
  if (!/^[A-Za-z0-9.-]+(?::[1-9][0-9]{0,4})?$/.test(value)) throw new Error(`${path} must be a valid HTTP Host authority`);
  const port = value.lastIndexOf(":") < 0 ? undefined : Number(value.slice(value.lastIndexOf(":") + 1));
  if (port !== undefined && (!Number.isInteger(port) || port > 65535)) throw new Error(`${path} has an invalid port`);
}
