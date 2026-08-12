import { randomUUID } from "node:crypto";
import { encodeTarBatch } from "../protocol/archive.ts";
import { protectPayload } from "../crypto/protection.ts";
import { buildBatchTopic } from "../protocol/topic.ts";
import type { AppConfig, Direction, TunnelBatch, TunnelRecord } from "../types.ts";

export interface BatchTransport { publish(topic: string, payload: Uint8Array): Promise<void>; }
export interface OutboundRecord { direction: Direction; toNodeId: string; record: TunnelRecord; }
interface EncodedBatch { topic: string; payload: Uint8Array; }

/** Batches ordered protocol records. Actual encoded payload size, not estimates, is the hard boundary. */
export class RecordBatcher {
  private readonly pending: OutboundRecord[] = [];
  private timer: ReturnType<typeof setTimeout> | undefined;
  private flushing: Promise<void> = Promise.resolve();
  private stopped = false;
  private nextPublishAt = 0;
  private queuedRecords = 0;

  public constructor(private readonly config: AppConfig, private readonly transport: BatchTransport, private readonly key: Uint8Array | undefined) {}

  enqueue(item: OutboundRecord): void {
    if (this.stopped) throw new Error("batcher is stopped");
    if (this.queuedRecords >= this.config.batch.maxQueuedRecords) throw new Error(`batch queue is full (${this.config.batch.maxQueuedRecords} records); refusing more outbound data`);
    this.pending.push(item);
    this.queuedRecords += 1;
    if (this.pending.length >= this.config.batch.maxRecordsPerBatch) { void this.flush(); return; }
    if (!this.timer) this.timer = setTimeout(() => { void this.flush(); }, this.config.batch.maxDelayMs);
  }

  async flush(): Promise<void> {
    if (this.timer) { clearTimeout(this.timer); this.timer = undefined; }
    if (!this.pending.length) return this.flushing;
    const records = this.pending.splice(0);
    this.flushing = this.flushing.then(() => this.publishGroups(records)).finally(() => { this.queuedRecords -= records.length; });
    return this.flushing;
  }
  async close(): Promise<void> { this.stopped = true; await this.flush(); }

  private async publishGroups(records: OutboundRecord[]): Promise<void> {
    const groups = new Map<string, OutboundRecord[]>();
    for (const item of records) {
      const key = `${item.direction}\u0000${item.toNodeId}`;
      const group = groups.get(key); if (group) group.push(item); else groups.set(key, [item]);
    }
    for (const group of groups.values()) await this.publishPacked(group);
  }

  private async publishPacked(items: OutboundRecord[]): Promise<void> {
    let current: OutboundRecord[] = [];
    let currentEncoded: EncodedBatch | undefined;
    for (const item of items) {
      const candidate = [...current, item];
      const candidateEncoded = await this.encodeItems(candidate);
      if (candidate.length <= this.config.batch.maxRecordsPerBatch && candidateEncoded.payload.byteLength <= this.config.batch.maxBatchBytes) {
        current = candidate;
        currentEncoded = candidateEncoded;
        continue;
      }
      if (currentEncoded) await this.publishEncoded(currentEncoded);
      const single = await this.encodeItems([item]);
      if (single.payload.byteLength > this.config.batch.maxBatchBytes) {
        throw new Error(`single ${item.record.type} record exceeds batch.maxBatchBytes=${this.config.batch.maxBatchBytes}; reduce tunnel record size`);
      }
      current = [item];
      currentEncoded = single;
    }
    if (currentEncoded) await this.publishEncoded(currentEncoded);
  }

  private async encodeItems(items: OutboundRecord[]): Promise<EncodedBatch> {
    const first = items[0]!;
    const topic = buildBatchTopic({ topicPrefix: this.config.mqtt.topicPrefix, direction: first.direction, toNodeId: first.toNodeId, fromNodeId: this.config.nodeId, archive: this.config.batch.archive, protection: this.config.batch.protection });
    const batch: TunnelBatch = { id: randomUUID(), records: items.map((item) => item.record) };
    const archive = await encodeTarBatch(batch, this.config.batch.archive === "tgz");
    return { topic, payload: await protectPayload(this.config.batch.protection, archive, topic, this.key) };
  }
  private async publishEncoded(encoded: EncodedBatch): Promise<void> {
    const waitMs = Math.max(0, this.nextPublishAt - Date.now());
    if (waitMs > 0) await Bun.sleep(waitMs);
    this.nextPublishAt = Date.now() + this.config.batch.minPublishIntervalMs;
    await this.transport.publish(encoded.topic, encoded.payload);
  }
}
