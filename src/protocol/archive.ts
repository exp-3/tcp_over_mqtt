import type { RecordType, TunnelBatch, TunnelProtocol, TunnelRecord } from "../types.ts";
import { PROTOCOLS, RECORD_TYPES } from "../types.ts";

const ROOT = "tom/v1";
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export interface ArchiveLimits {
  maxRecords: number;
  /** Maximum total uncompressed entry bytes after archive decoding. */
  maxBytes: number;
  /** Optional ratio cap between decoded entry bytes and compressed archive payload. */
  maxCompressionRatio?: number;
}

export async function encodeTarBatch(batch: TunnelBatch, gzip: boolean): Promise<Uint8Array> {
  if (!batch.id || batch.records.length === 0) throw new Error("batch must contain an id and at least one record");
  const files: Record<string, string | Uint8Array> = {
    [`${ROOT}/batch/id`]: batch.id,
    [`${ROOT}/batch/record-count`]: String(batch.records.length),
  };
  batch.records.forEach((record, index) => {
    const base = `${ROOT}/records/${String(index + 1).padStart(6, "0")}`;
    files[`${base}/tunnel-id`] = record.tunnelId;
    files[`${base}/sequence`] = record.sequence.toString();
    files[`${base}/type`] = record.type;
    if (record.protocol) files[`${base}/protocol`] = record.protocol;
    if (record.endpoint) files[`${base}/endpoint`] = record.endpoint;
    if (record.flags?.length) files[`${base}/flags`] = record.flags.join(",");
    if (record.errorCode) files[`${base}/error-code`] = record.errorCode;
    if (record.errorMessage) files[`${base}/error-message`] = record.errorMessage;
    if (record.windowBytes !== undefined) files[`${base}/window-bytes`] = String(record.windowBytes);
    if (record.data) files[`${base}/data`] = record.data;
  });
  return new Uint8Array(await new Bun.Archive(files, gzip ? { compress: "gzip" } : undefined).bytes());
}

export async function decodeTarBatch(payload: Uint8Array, limits: ArchiveLimits): Promise<TunnelBatch> {
  if (payload.byteLength > limits.maxBytes) throw new Error("archive exceeds configured byte limit");
  const entries = await new Bun.Archive(payload).files();
  if (entries.size > 2 + limits.maxRecords * 10) throw new Error("archive contains too many entries");
  const fields = new Map<string, Uint8Array>();
  let decodedBytes = 0;
  for (const [path, file] of entries) {
    validateTarPath(path);
    if (fields.has(path)) throw new Error(`duplicate TAR path '${path}'`);
    if (file.size > limits.maxBytes || decodedBytes + file.size > limits.maxBytes) {
      throw new Error("archive decoded entries exceed configured byte limit");
    }
    const bytes = await file.bytes();
    decodedBytes += bytes.byteLength;
    if (decodedBytes > limits.maxBytes) throw new Error("archive decoded entries exceed configured byte limit");
    fields.set(path, bytes);
  }
  if (limits.maxCompressionRatio !== undefined && payload.byteLength > 0 && decodedBytes / payload.byteLength > limits.maxCompressionRatio) {
    throw new Error("archive exceeds configured compression ratio limit");
  }
  const id = readText(fields, `${ROOT}/batch/id`, true)!;
  const recordCount = readInteger(fields, `${ROOT}/batch/record-count`, true)!;
  if (recordCount < 1 || recordCount > limits.maxRecords) throw new Error("invalid batch record-count");
  const records: TunnelRecord[] = [];
  const consumed = new Set([`${ROOT}/batch/id`, `${ROOT}/batch/record-count`]);
  for (let index = 1; index <= recordCount; index++) {
    const base = `${ROOT}/records/${String(index).padStart(6, "0")}`;
    const tunnelId = readText(fields, `${base}/tunnel-id`, true)!;
    const sequenceText = readText(fields, `${base}/sequence`, true)!;
    let sequence: bigint;
    try { sequence = BigInt(sequenceText); } catch { throw new Error(`invalid sequence '${sequenceText}'`); }
    if (sequence < 0n) throw new Error("sequence cannot be negative");
    const type = readText(fields, `${base}/type`, true)! as RecordType;
    if (!RECORD_TYPES.includes(type)) throw new Error(`invalid record type '${type}'`);
    const protocolText = readText(fields, `${base}/protocol`, false);
    const protocol = protocolText as TunnelProtocol | undefined;
    if (protocol && !PROTOCOLS.includes(protocol)) throw new Error(`invalid protocol '${protocol}'`);
    const endpoint = readText(fields, `${base}/endpoint`, false);
    const flagsText = readText(fields, `${base}/flags`, false);
    const errorCode = readText(fields, `${base}/error-code`, false);
    const errorMessage = readText(fields, `${base}/error-message`, false);
    const windowBytes = readInteger(fields, `${base}/window-bytes`, false);
    const data = fields.get(`${base}/data`);
    for (const suffix of ["tunnel-id", "sequence", "type", "protocol", "endpoint", "flags", "error-code", "error-message", "window-bytes", "data"]) {
      if (fields.has(`${base}/${suffix}`)) consumed.add(`${base}/${suffix}`);
    }
    if (type === "OPEN" && (sequence !== 0n || !protocol || !endpoint)) {
      throw new Error("OPEN requires sequence=0, protocol, and endpoint");
    }
    if (type === "OPEN_OK" && sequence !== 0n) throw new Error("OPEN_OK requires sequence=0");
    records.push({
      tunnelId,
      sequence,
      type,
      ...(protocol ? { protocol } : {}),
      ...(endpoint ? { endpoint } : {}),
      ...(flagsText ? { flags: flagsText.split(",").filter(Boolean) } : {}),
      ...(errorCode ? { errorCode } : {}),
      ...(errorMessage ? { errorMessage } : {}),
      ...(windowBytes !== undefined ? { windowBytes } : {}),
      ...(data ? { data } : {}),
    });
  }
  const unknown = [...fields.keys()].filter((key) => !consumed.has(key));
  if (unknown.length) throw new Error(`unknown or non-contiguous TAR path '${unknown[0]}'`);
  return { id, records };
}

function validateTarPath(path: string): void {
  if (!path.startsWith(`${ROOT}/`)) throw new Error(`TAR path must begin with ${ROOT}/`);
  if (path.startsWith("/") || path.includes("\\") || path.split("/").some((part) => part === ".." || part === "." || part === "")) {
    throw new Error(`unsafe TAR path '${path}'`);
  }
}

function readText(fields: Map<string, Uint8Array>, path: string, required: boolean): string | undefined {
  const value = fields.get(path);
  if (!value) {
    if (required) throw new Error(`missing TAR field '${path}'`);
    return undefined;
  }
  if (value.byteLength > 65_536) throw new Error(`TAR text field '${path}' is too large`);
  return textDecoder.decode(value);
}

function readInteger(fields: Map<string, Uint8Array>, path: string, required: boolean): number | undefined {
  const value = readText(fields, path, required);
  if (value === undefined) return undefined;
  if (!/^\d+$/.test(value)) throw new Error(`TAR field '${path}' must be an unsigned integer`);
  const number = Number(value);
  if (!Number.isSafeInteger(number)) throw new Error(`TAR field '${path}' exceeds safe integer range`);
  return number;
}
