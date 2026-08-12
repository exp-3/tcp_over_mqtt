import { describe, expect, test } from "bun:test";
import { protectPayload, unprotectPayload } from "../src/crypto/protection.ts";

const bytes = Uint8Array.from([0, 1, 2, 128, 255]);
const key = new TextEncoder().encode("test key");

describe("payload protection", () => {
  for (const mode of ["plain", "aead", "rc4"] as const) {
    test(`${mode} round trip`, async () => {
      const protectedBytes = await protectPayload(mode, bytes, "topic/a", key);
      expect(await unprotectPayload(mode, protectedBytes, "topic/a", key)).toEqual(bytes);
    });
  }

  test("AEAD authenticates topic AAD", async () => {
    const protectedBytes = await protectPayload("aead", bytes, "topic/a", key);
    await expect(unprotectPayload("aead", protectedBytes, "topic/b", key)).rejects.toThrow();
  });
});
