import { describe, expect, test } from "bun:test";
import { decodeTarBatch, encodeTarBatch } from "../src/protocol/archive.ts";
import type { TunnelBatch } from "../src/types.ts";

const batch: TunnelBatch = {
  id: "batch-1",
  records: [
    { tunnelId: "t-1", sequence: 0n, type: "OPEN", protocol: "http", endpoint: "example.com:80", data: Uint8Array.from([0, 255, 1]) },
    { tunnelId: "t-2", sequence: 5n, type: "DATA", data: new TextEncoder().encode("hello") },
  ],
};

describe("TAR batches", () => {
  for (const gzip of [false, true]) {
    test(`${gzip ? "TGZ" : "TAR"} round trip with binary records`, async () => {
      const encoded = await encodeTarBatch(batch, gzip);
      const files = await new Bun.Archive(encoded).files();
      expect(files.has("tom/v1/records/000001/data")).toBeTrue();
      const decoded = await decodeTarBatch(encoded, { maxRecords: 64, maxBytes: 1_000_000 });
      expect(decoded).toEqual(batch);
    });
  }

  test("rejects an unknown internal path", async () => {
    const bad = await new Bun.Archive({
      "tom/v1/batch/id": "x",
      "tom/v1/batch/record-count": "1",
      "tom/v1/records/000001/tunnel-id": "t",
      "tom/v1/records/000001/sequence": "1",
      "tom/v1/records/000001/type": "DATA",
      "tom/v1/records/000001/surprise": "no",
    }).bytes();
    await expect(decodeTarBatch(new Uint8Array(bad), { maxRecords: 2, maxBytes: 1_000_000 })).rejects.toThrow(/unknown/);
  });
});
