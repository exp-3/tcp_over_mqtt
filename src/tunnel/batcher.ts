import { randomUUID } from "node:crypto";
import { encodeTarBatch } from "../protocol/archive.ts";
import { protectPayload } from "../crypto/protection.ts";
import { buildBatchTopic } from "../protocol/topic.ts";
import type { AppConfig, Direction, TunnelBatch, TunnelRecord } from "../types.ts";

export interface BatchTransport {
  publish(topic: string, payload: Uint8Array): Promise<void>;
}

export interface OutboundRecord {
  direction: Direction;
  toNodeId: string;
  record: TunnelRecord;
}

/** Batches protocol records into independent TAR/TAR.GZ MQTT payloads. */
export class RecordBatcher {
  private readonly pending: OutboundRecord[] = [];
  private timer: ReturnType<typeof setTimeout> | undefined;
  private flushing: Promise<void> = Promise.resolve();
  private stopped = false;
  private estimatedBytes = 0;

  public constructor(
    private readonly config: AppConfig,
    private readonly transport: BatchTransport,
    private readonly key: Uint8Array | undefined,
  ) {}

  enqueue(item: OutboundRecord): void {
    if (this.stopped) throw new Error("batcher is stopped");
    const estimated = estimateRecordBytes(item.record);
    if (this.pending.length > 0 && (this.pending.length >= this.config.batch.maxRecordsPerBatch || this.estimatedBytes + estimated > this.config.batch.maxBatchBytes)) {
      void this.flush();
    }
    this.pending.push(item);
    this.estimatedBytes += estimated;
    if (this.pending.length >= this.config.batch.maxRecordsPerBatch || this.estimatedBytes >= this.config.batch.maxBatchBytes) {
      void this.flush();
      return;
    }
    if (!this.timer) this.timer = setTimeout(() => { void this.flush(); }, this.config.batch.maxDelayMs);
  }

  async flush(): Promise<void> {
    if (this.timer) { clearTimeout(this.timer); this.timer = undefined; }
    if (this.pending.length === 0) return this.flushing;
    const records = this.pending.splice(0);
    this.estimatedBytes = 0;
    this.flushing = this.flushing.then(() => this.publishGroups(records));
    return this.flushing;
  }

  async close(): Promise<void> {
    this.stopped = true;
    await this.flush();
  }

  private async publishGroups(records: OutboundRecord[]): Promise<void> {
    const groups = new Map<string, OutboundRecord[]>();
    for (const item of records) {
      const key = `${item.direction}\u0000${item.toNodeId}`;
      const group = groups.get(key);
      if (group) group.push(item); else groups.set(key, [item]);
    }
    for (const group of groups.values()) await this.publishSplit(group);
  }

  private async publishSplit(items: OutboundRecord[]): Promise<void> {
    const first = items[0]!;
    const topic = buildBatchTopic({
      topicPrefix: this.config.mqtt.topicPrefix,
      direction: first.direction,
      toNodeId: first.toNodeId,
      fromNodeId: this.config.nodeId,
      archive: this.config.batch.archive,
      protection: this.config.batch.protection,
    });
    const payload = await this.encode(topic, { id: randomUUID(), records: items.map((item) => item.record) });
    if (payload.byteLength <= this.config.batch.maxBatchBytes) {
      await this.transport.publish(topic, payload);
      return;
    }
    if (items.length === 1) {
      throw new Error(`single ${items[0]!.record.type} record produces ${payload.byteLength} bytes, exceeding batch.maxBatchBytes=${this.config.batch.maxBatchBytes}`);
    }
    const midpoint = Math.ceil(items.length / 2);
    await this.publishSplit(items.slice(0, midpoint));
    await this.publishSplit(items.slice(midpoint));
  }

  private async encode(topic: string, batch: TunnelBatch): Promise<Uint8Array> {
    const archive = await encodeTarBatch(batch, this.config.batch.archive === "tgz");
    return protectPayload(this.config.batch.protection, archive, topic, this.key);
  }
}

function estimateRecordBytes(record: TunnelRecord): number {
  return 1_536 + (record.data?.byteLength ?? 0) + (record.endpoint?.length ?? 0) + (record.errorMessage?.length ?? 0);
}
