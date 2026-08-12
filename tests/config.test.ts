import { describe, expect, test } from "bun:test";
import { parseConfig } from "../src/config/load.ts";
import { resolveSecretValue } from "../src/config/secrets.ts";

function baseConfig(): Record<string, any> {
  return {
    role: "server",
    nodeId: "server-a",
    mqtt: { url: "mqtt://localhost:1883", topicPrefix: "tenant/test", protocolVersion: 5, qos: 1 },
    protocols: { tcp: true, tls: false, http: false, socks: true },
    batch: { archive: "tar", protection: "plain" },
    tunnel: {},
    egress: { allowedHosts: [], allowedPorts: [], denyPrivateNetworks: false },
    http: {},
    tls: {},
    socks: { allowedHosts: [], allowedPorts: [] },
    listeners: [],
  };
}

describe("configuration", () => {
  test("environment secrets override configuration fallbacks", () => {
    const name = "TOM_TEST_SECRET_OVERRIDE";
    process.env[name] = "from-environment";
    try {
      expect(resolveSecretValue(name, "from-config")).toBe("from-environment");
    } finally {
      delete process.env[name];
    }
  });

  test("configuration secrets are used when environment variables are absent", () => {
    const name = "TOM_TEST_SECRET_FALLBACK";
    delete process.env[name];
    expect(resolveSecretValue(name, "from-config")).toBe("from-config");
  });

  test("a configured secret environment variable still fails without a fallback", () => {
    const name = "TOM_TEST_SECRET_MISSING";
    delete process.env[name];
    expect(() => resolveSecretValue(name, undefined)).toThrow(/no configuration fallback/);
  });

  test("secret environment names use the TOM_ prefix", () => {
    const raw = baseConfig();
    raw.mqtt = {
      url: "mqtt://localhost:1883",
      topicPrefix: "tenant/test",
      usernameEnv: "MQTT_USERNAME",
    };
    expect(() => parseConfig(raw)).toThrow(/mqtt\.usernameEnv must start with 'TOM_'/);
  });

  test("secret fallbacks are accepted in configuration", () => {
    const raw = baseConfig();
    raw.mqtt = {
      url: "mqtt://localhost:1883",
      topicPrefix: "tenant/test",
      username: "fallback-user",
      password: "fallback-password",
      usernameEnv: "TOM_MQTT_USERNAME",
      passwordEnv: "TOM_MQTT_PASSWORD",
    };
    raw.batch = {
      archive: "tar",
      protection: "aead",
      key: "fallback-key",
      keyEnv: "TOM_BATCH_KEY",
    };
    const config = parseConfig(raw);
    expect(config.mqtt.username).toBe("fallback-user");
    expect(config.mqtt.password).toBe("fallback-password");
    expect(config.batch.key).toBe("fallback-key");
  });

  test("a protected batch may use a configuration key without an environment variable", () => {
    const raw = baseConfig();
    raw.batch = { archive: "tar", protection: "aead", key: "fallback-key" };
    expect(parseConfig(raw).batch.key).toBe("fallback-key");
  });

  test("batch publish throttling has a safe default", () => {
    expect(parseConfig(baseConfig()).batch.minPublishIntervalMs).toBe(5);
    expect(parseConfig(baseConfig()).batch.maxDelayMs).toBe(50);
    expect(parseConfig(baseConfig()).batch.maxQueuedRecords).toBe(4096);
  });

  test("HTTP listener requires a fixed origin and rejects legacy TCP target fields", () => {
    const raw = baseConfig();
    raw.protocols.http = true;
    raw.http = { allowedHosts: [], allowedPorts: [] };
    raw.listeners = [{ name: "http", type: "http", listenHost: "127.0.0.1", listenPort: 18080, toNodeId: "peer-a", originHost: "origin.example", originPort: 443, originProtocol: "https" }];
    const listener = parseConfig(raw).listeners[0]!;
    expect(listener.originProtocol).toBe("https");
    expect(listener.originRequestHost).toBeUndefined();
    raw.listeners[0].targetHost = "legacy.example";
    expect(() => parseConfig(raw)).toThrow(/originHost\/originPort/);
  });

  test("HTTP listener validates an optional originRequestHost", () => {
    const raw = baseConfig();
    raw.protocols.http = true;
    raw.http = { allowedHosts: [], allowedPorts: [] };
    raw.listeners = [{ name: "http", type: "http", listenHost: "127.0.0.1", listenPort: 18080, toNodeId: "peer-a", originHost: "origin.example", originPort: 8443, originProtocol: "https", originRequestHost: "public.example:8443" }];
    expect(parseConfig(raw).listeners[0]!.originRequestHost).toBe("public.example:8443");
    raw.listeners[0].originRequestHost = "bad host/path";
    expect(() => parseConfig(raw)).toThrow(/originRequestHost/);
  });

  test("empty SOCKS allow arrays explicitly mean unrestricted", () => {
    const config = parseConfig(baseConfig());
    expect(config.socks.allowedHosts).toEqual([]);
    expect(config.socks.allowedPorts).toEqual([]);
  });

  test("enabled SOCKS requires allowedHosts", () => {
    const raw = baseConfig();
    delete (raw.socks as { allowedHosts?: string[] }).allowedHosts;
    expect(() => parseConfig(raw)).toThrow(/socks\.allowedHosts.*required/);
  });

  test("enabled SOCKS requires allowedPorts", () => {
    const raw = baseConfig();
    delete (raw.socks as { allowedPorts?: number[] }).allowedPorts;
    expect(() => parseConfig(raw)).toThrow(/socks\.allowedPorts.*required/);
  });

  test("egress allow arrays are always explicit", () => {
    const raw = baseConfig();
    delete (raw.egress as { allowedHosts?: string[] }).allowedHosts;
    expect(() => parseConfig(raw)).toThrow(/egress\.allowedHosts.*required/);
  });
});

test("JSONC examples are accepted while JSON5-only syntax is rejected", async () => {
  const connector = await import("../src/config/load.ts").then(({ loadConfig }) => loadConfig("config/connector.example.jsonc"));
  expect(connector.role).toBe("connector");

  const path = `/tmp/tcp-over-mqtt-json5-${Bun.randomUUIDv7()}.jsonc`;
  await Bun.write(path, `{ role: "server" }`);
  try {
    await expect(import("../src/config/load.ts").then(({ loadConfig }) => loadConfig(path))).rejects.toThrow(/JSONC/);
  } finally {
    await Bun.file(path).delete();
  }
});
