import { describe, expect, test } from "bun:test";
import { decodeTarBatch } from "../src/protocol/archive.ts";
import { unprotectPayload } from "../src/crypto/protection.ts";
import { parseBatchTopic } from "../src/protocol/topic.ts";
import { RecordBatcher, type BatchTransport } from "../src/tunnel/batcher.ts";
import type { AppConfig } from "../src/types.ts";

function config(): AppConfig {
  return {
    role: "connector", nodeId: "connector-a",
    mqtt: { url: "mqtt://unused", clientId: "connector-a", topicPrefix: "tenant/test", protocolVersion: 5, qos: 1, rejectUnauthorized: true },
    protocols: { tcp: true, tls: false, http: false, socks: false },
    batch: { archive: "tgz", protection: "aead", keyEnv: "TOM_IGNORED", maxBatchBytes: 48_000, maxRecordsPerBatch: 64, maxDelayMs: 1, minPublishIntervalMs: 0, maxQueuedRecords: 4096, maxDecompressedBytes: 1_000_000, maxCompressionRatio: 100 },
    tunnel: { maxConcurrentTunnels: 10, maxBufferedBytesPerTunnel: 65_536, idleTimeoutMs: 60_000, connectTimeoutMs: 1_000 },
    egress: { allowedHosts: [], allowedPorts: [], denyPrivateNetworks: false },
    http: { allowedHosts: [], allowedPorts: [], denyPrivateNetworks: false, requestHeaderMaxBytes: 4096, requestHeaderTimeoutMs: 1000, responseHeaderMaxBytes: 4096, responseHeaderTimeoutMs: 1000 },
    tls: { allowedHosts: [], allowedPorts: [], denyPrivateNetworks: false, requireSni: true, requireEndpointSniMatch: true, allowEch: false, allowedEchPublicNames: [], legacySsl: "reject", clientHelloMaxBytes: 4096, clientHelloTimeoutMs: 1000 },
    socks: { allowedHosts: [], allowedPorts: [], denyPrivateNetworks: false, connectTimeoutMs: 1000 },
    listeners: [],
  };
}

describe("record batcher", () => {
  test("groups many tunnel records into one protected TGZ MQTT payload", async () => {
    const published: Array<{ topic: string; payload: Uint8Array }> = [];
    const transport: BatchTransport = { publish: async (topic, payload) => { published.push({ topic, payload }); } };
    const key = new TextEncoder().encode("batch test key");
    const batcher = new RecordBatcher(config(), transport, key);
    batcher.enqueue({ direction: "c2s", toNodeId: "server-a", record: { tunnelId: "a", sequence: 0n, type: "OPEN", protocol: "tcp", endpoint: "example.com:443" } });
    batcher.enqueue({ direction: "c2s", toNodeId: "server-a", record: { tunnelId: "b", sequence: 0n, type: "OPEN", protocol: "tcp", endpoint: "example.net:443" } });
    await batcher.flush();
    expect(published).toHaveLength(1);
    const topic = published[0]!.topic;
    expect(parseBatchTopic(topic, "tenant/test").protection).toBe("aead");
    const archive = await unprotectPayload("aead", published[0]!.payload, topic, key);
    const decoded = await decodeTarBatch(archive, { maxRecords: 64, maxBytes: 1_000_000, maxCompressionRatio: 100 });
    expect(decoded.records.map((record) => record.tunnelId)).toEqual(["a", "b"]);
  });
});

test("publishes the existing batch before a next record that would exceed the actual payload limit", async () => {
  const published: Array<{ topic: string; payload: Uint8Array }> = [];
  const cfg = config();
  cfg.batch.archive = "tar";
  cfg.batch.protection = "plain";
  cfg.batch.maxBatchBytes = 13_000;
  const batcher = new RecordBatcher(cfg, { publish: async (topic, payload) => { published.push({ topic, payload }); } }, undefined);
  const bytes = new Uint8Array(1_200).fill(7);
  batcher.enqueue({ direction: "c2s", toNodeId: "server-a", record: { tunnelId: "a", sequence: 1n, type: "DATA", data: bytes } });
  batcher.enqueue({ direction: "c2s", toNodeId: "server-a", record: { tunnelId: "a", sequence: 2n, type: "DATA", data: bytes } });
  await batcher.flush();
  expect(published.length).toBeGreaterThan(1);
  expect(published.every((entry) => entry.payload.byteLength <= cfg.batch.maxBatchBytes)).toBeTrue();
});
