import { describe, expect, test } from "bun:test";
import { parseConfig } from "../src/config/load.ts";

function baseConfig() {
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
