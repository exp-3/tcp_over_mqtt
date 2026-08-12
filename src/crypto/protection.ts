import type { ProtectionMode } from "../types.ts";

const AEAD_MAGIC = new TextEncoder().encode("TMA1");
const RC4_MAGIC = new TextEncoder().encode("TMR1");

export function readKeyFromEnv(envName: string | undefined): Uint8Array | undefined {
  if (!envName) return undefined;
  const value = process.env[envName];
  if (!value) throw new Error(`environment variable ${envName} is required`);
  if (value.startsWith("base64:")) return Uint8Array.from(Buffer.from(value.slice(7), "base64"));
  if (value.startsWith("hex:")) return Uint8Array.from(Buffer.from(value.slice(4), "hex"));
  return new TextEncoder().encode(value);
}

export async function protectPayload(
  mode: ProtectionMode,
  payload: Uint8Array,
  aad: string,
  key?: Uint8Array,
): Promise<Uint8Array> {
  if (mode === "plain") return payload;
  if (!key || key.byteLength === 0) throw new Error(`${mode} protection requires a key`);
  if (mode === "aead") return encryptAead(payload, aad, key);
  return encryptRc4(payload, aad, key);
}

export async function unprotectPayload(
  mode: ProtectionMode,
  payload: Uint8Array,
  aad: string,
  key?: Uint8Array,
): Promise<Uint8Array> {
  if (mode === "plain") return payload;
  if (!key || key.byteLength === 0) throw new Error(`${mode} protection requires a key`);
  if (mode === "aead") return decryptAead(payload, aad, key);
  return decryptRc4(payload, aad, key);
}

async function deriveAesKey(key: Uint8Array): Promise<CryptoKey> {
  const digest = await crypto.subtle.digest("SHA-256", asArrayBuffer(key));
  return crypto.subtle.importKey("raw", digest, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function encryptAead(payload: Uint8Array, aad: string, key: Uint8Array): Promise<Uint8Array> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await deriveAesKey(key);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: asArrayBuffer(new TextEncoder().encode(aad)), tagLength: 128 },
    aesKey,
    asArrayBuffer(payload),
  ));
  return concat(AEAD_MAGIC, nonce, encrypted);
}

async function decryptAead(payload: Uint8Array, aad: string, key: Uint8Array): Promise<Uint8Array> {
  if (payload.byteLength < 4 + 12 + 16 || !equalPrefix(payload, AEAD_MAGIC)) throw new Error("invalid AEAD payload");
  const nonce = payload.slice(4, 16);
  const encrypted = payload.slice(16);
  const aesKey = await deriveAesKey(key);
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce, additionalData: asArrayBuffer(new TextEncoder().encode(aad)), tagLength: 128 },
    aesKey,
    asArrayBuffer(encrypted),
  ));
}

async function rc4Key(master: Uint8Array, aad: string, nonce: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", asArrayBuffer(concat(master, nonce, new TextEncoder().encode(aad)))));
}

async function encryptRc4(payload: Uint8Array, aad: string, key: Uint8Array): Promise<Uint8Array> {
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const derived = await rc4Key(key, aad, nonce);
  return concat(RC4_MAGIC, nonce, rc4(derived, payload));
}

async function decryptRc4(payload: Uint8Array, aad: string, key: Uint8Array): Promise<Uint8Array> {
  if (payload.byteLength < 20 || !equalPrefix(payload, RC4_MAGIC)) throw new Error("invalid RC4 payload");
  const nonce = payload.slice(4, 20);
  const derived = await rc4Key(key, aad, nonce);
  return rc4(derived, payload.slice(20));
}

function rc4(key: Uint8Array, input: Uint8Array): Uint8Array {
  const state = Uint8Array.from({ length: 256 }, (_, index) => index);
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + state[i]! + key[i % key.length]!) & 255;
    [state[i], state[j]] = [state[j]!, state[i]!];
  }
  const output = new Uint8Array(input.byteLength);
  let i = 0;
  j = 0;
  for (let n = 0; n < input.byteLength; n++) {
    i = (i + 1) & 255;
    j = (j + state[i]!) & 255;
    [state[i], state[j]] = [state[j]!, state[i]!];
    output[n] = input[n]! ^ state[(state[i]! + state[j]!) & 255]!;
  }
  return output;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

function equalPrefix(value: Uint8Array, prefix: Uint8Array): boolean {
  return prefix.every((byte, index) => value[index] === byte);
}

function asArrayBuffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}
