import { connectAsync, type MqttClient } from "mqtt";
import { resolveSecretValue } from "../config/secrets.ts";
import { decodeTarBatch } from "../protocol/archive.ts";
import { unprotectPayload, readKeyFromEnv } from "../crypto/protection.ts";
import { buildNodeSubscription, parseBatchTopic } from "../protocol/topic.ts";
import type { AppConfig, TunnelBatch } from "../types.ts";
import type { BatchTransport } from "../tunnel/batcher.ts";

export class MqttBatchNode implements BatchTransport {
  private client: MqttClient | undefined;
  private readonly seenBatches = new Set<string>();
  private readonly seenOrder: string[] = [];
  private readonly key: Uint8Array | undefined;
  public onBatch: ((batch: TunnelBatch, context: { direction: "c2s" | "s2c"; fromNodeId: string }) => Promise<void>) | undefined;
  public onError: ((error: Error) => void) | undefined;

  public constructor(private readonly config: AppConfig) {
    this.key = readKeyFromEnv(config.batch.keyEnv, config.batch.key);
  }

  get protectionKey(): Uint8Array | undefined { return this.key; }

  async start(): Promise<void> {
    const username = resolveSecretValue(this.config.mqtt.usernameEnv, this.config.mqtt.username);
    const password = resolveSecretValue(this.config.mqtt.passwordEnv, this.config.mqtt.password);
    this.client = await connectAsync(this.config.mqtt.url, {
      clientId: this.config.mqtt.clientId,
      protocolVersion: this.config.mqtt.protocolVersion,
      clean: true,
      reconnectPeriod: 1_000,
      rejectUnauthorized: this.config.mqtt.rejectUnauthorized,
      ...(username !== undefined ? { username } : {}),
      ...(password !== undefined ? { password } : {}),
    });
    this.client.on("error", (error) => this.onError?.(error));
    this.client.on("message", (topic, payload) => { void this.handleMessage(topic, new Uint8Array(payload)); });
    await this.client.subscribeAsync(buildNodeSubscription(this.config.mqtt.topicPrefix, this.config.nodeId), { qos: this.config.mqtt.qos });
  }

  async publish(topic: string, payload: Uint8Array): Promise<void> {
    if (!this.client) throw new Error("MQTT client is not started");
    await this.client.publishAsync(topic, Buffer.from(payload), {
      qos: this.config.mqtt.qos,
      retain: false,
      ...(this.config.mqtt.protocolVersion === 5 ? { properties: { messageExpiryInterval: Math.max(1, Math.ceil(this.config.tunnel.idleTimeoutMs / 1000)) } } : {}),
    });
  }

  async close(): Promise<void> {
    const client = this.client;
    this.client = undefined;
    if (!client) return;
    await new Promise<void>((resolve, reject) => client.end(false, {}, (error) => error ? reject(error) : resolve()));
  }

  private async handleMessage(topic: string, payload: Uint8Array): Promise<void> {
    try {
      const parts = parseBatchTopic(topic, this.config.mqtt.topicPrefix);
      if (parts.toNodeId !== this.config.nodeId || parts.fromNodeId === this.config.nodeId) return;
      if (parts.archive !== this.config.batch.archive || parts.protection !== this.config.batch.protection) {
        throw new Error("MQTT batch archive/protection profile does not match local configuration");
      }
      if (payload.byteLength > this.config.batch.maxBatchBytes) throw new Error("MQTT batch exceeds batch.maxBatchBytes");
      const archive = await unprotectPayload(parts.protection, payload, topic, this.key);
      const batch = await decodeTarBatch(archive, {
        maxRecords: this.config.batch.maxRecordsPerBatch,
        maxBytes: this.config.batch.maxDecompressedBytes,
        maxCompressionRatio: this.config.batch.maxCompressionRatio,
      });
      const identity = `${parts.fromNodeId}\u0000${parts.direction}\u0000${batch.id}`;
      if (this.seenBatches.has(identity)) return;
      this.remember(identity);
      await this.onBatch?.(batch, { direction: parts.direction, fromNodeId: parts.fromNodeId });
    } catch (error) {
      this.onError?.(asError(error));
    }
  }

  private remember(identity: string): void {
    this.seenBatches.add(identity);
    this.seenOrder.push(identity);
    const maximum = 8_192;
    if (this.seenOrder.length > maximum) this.seenBatches.delete(this.seenOrder.shift()!);
  }
}

function asError(error: unknown): Error { return error instanceof Error ? error : new Error(String(error)); }
