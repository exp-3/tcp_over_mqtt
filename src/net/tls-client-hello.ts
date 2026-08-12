import type { Endpoint, } from "../protocol/endpoint.ts";

const ECH_EXTENSION_IDS = new Set([0xfe0d, 0xffce]);

export interface TlsClientHelloInfo {
  sni?: string;
  alpn: string[];
  ech: boolean;
  legacyVersion: number;
  recordVersion: number;
  legacySsl: boolean;
  consumedBytes: number;
}

export type TlsInspection = { status: "incomplete" } | { status: "complete"; info: TlsClientHelloInfo };

export function inspectTlsClientHello(input: Uint8Array, maxBytes: number): TlsInspection {
  if (input.byteLength > maxBytes) throw new Error(`TLS ClientHello exceeds ${maxBytes} bytes`);
  if (input.byteLength < 2) return { status: "incomplete" };
  if ((input[0]! & 0x80) !== 0) {
    const length = ((input[0]! & 0x7f) << 8) | input[1]!;
    if (input.byteLength < length + 2) return { status: "incomplete" };
    if (input[2] !== 1) throw new Error("unsupported SSLv2 record");
    return { status: "complete", info: { alpn: [], ech: false, legacyVersion: readU16(input, 3), recordVersion: 0x0002, legacySsl: true, consumedBytes: length + 2 } };
  }

  const handshakeParts: Uint8Array[] = [];
  let offset = 0;
  let recordVersion = 0;
  let consumedBytes = 0;
  while (true) {
    if (input.byteLength - offset < 5) return { status: "incomplete" };
    const contentType = input[offset]!;
    recordVersion = readU16(input, offset + 1);
    const recordLength = readU16(input, offset + 3);
    if (recordLength > 18_432) throw new Error("oversized TLS record");
    if (input.byteLength - offset - 5 < recordLength) return { status: "incomplete" };
    if (contentType !== 22) throw new Error("first TLS flight is not a handshake record");
    handshakeParts.push(input.subarray(offset + 5, offset + 5 + recordLength));
    offset += 5 + recordLength;
    consumedBytes = offset;
    const handshake = concat(handshakeParts);
    if (handshake.byteLength < 4) continue;
    if (handshake[0] !== 1) throw new Error("first TLS handshake is not ClientHello");
    const helloLength = readU24(handshake, 1);
    if (helloLength > maxBytes) throw new Error(`TLS ClientHello exceeds ${maxBytes} bytes`);
    if (handshake.byteLength < helloLength + 4) continue;
    return { status: "complete", info: parseClientHello(handshake.subarray(4, 4 + helloLength), recordVersion, consumedBytes) };
  }
}

export function assertTlsIdentity(
  info: TlsClientHelloInfo,
  endpoint: Endpoint,
  options: {
    requireSni: boolean;
    requireEndpointSniMatch: boolean;
    allowEch: boolean;
    allowedEchPublicNames: string[];
    legacySsl: "reject" | "static-route-only";
  },
): void {
  if (info.legacySsl && options.legacySsl === "reject") throw new Error("legacy SSL is disabled");
  if (info.ech) {
    if (!options.allowEch) throw new Error("TLS ECH is disabled");
    if (options.allowedEchPublicNames.length > 0) {
      if (!info.sni || !options.allowedEchPublicNames.some((host) => normalize(host) === normalize(info.sni!))) {
        throw new Error("TLS ECH public name is not allowed");
      }
    }
    return;
  }
  if (!info.sni) {
    if (options.requireSni && !(info.legacySsl && options.legacySsl === "static-route-only")) {
      throw new Error("TLS ClientHello does not contain SNI");
    }
    return;
  }
  if (options.requireEndpointSniMatch && normalize(info.sni) !== normalize(endpoint.host)) {
    throw new Error(`TLS SNI '${info.sni}' does not match endpoint '${endpoint.host}'`);
  }
}

function parseClientHello(hello: Uint8Array, recordVersion: number, consumedBytes: number): TlsClientHelloInfo {
  if (hello.byteLength < 34) throw new Error("truncated TLS ClientHello");
  const legacyVersion = readU16(hello, 0);
  let offset = 34;
  const sessionLength = hello[offset]!;
  offset += 1 + sessionLength;
  offset = skipVector16(hello, offset, "cipher suites");
  if (offset >= hello.byteLength) throw new Error("truncated TLS compression methods");
  const compressionLength = hello[offset]!;
  offset += 1 + compressionLength;
  if (offset > hello.byteLength) throw new Error("truncated TLS compression methods");
  if (offset === hello.byteLength) {
    return { alpn: [], ech: false, legacyVersion, recordVersion, legacySsl: legacyVersion <= 0x0300, consumedBytes };
  }
  if (offset + 2 > hello.byteLength) throw new Error("truncated TLS extensions length");
  const extensionsLength = readU16(hello, offset);
  offset += 2;
  const extensionsEnd = offset + extensionsLength;
  if (extensionsEnd !== hello.byteLength) throw new Error("invalid TLS extensions length");
  let sni: string | undefined;
  let ech = false;
  let alpn: string[] = [];
  while (offset < extensionsEnd) {
    if (offset + 4 > extensionsEnd) throw new Error("truncated TLS extension");
    const type = readU16(hello, offset);
    const length = readU16(hello, offset + 2);
    offset += 4;
    if (offset + length > extensionsEnd) throw new Error("truncated TLS extension data");
    const value = hello.subarray(offset, offset + length);
    if (type === 0) sni = parseSni(value);
    else if (type === 16) alpn = parseAlpn(value);
    else if (ECH_EXTENSION_IDS.has(type)) ech = true;
    offset += length;
  }
  return {
    ...(sni ? { sni } : {}),
    alpn,
    ech,
    legacyVersion,
    recordVersion,
    legacySsl: legacyVersion <= 0x0300,
    consumedBytes,
  };
}

function parseSni(value: Uint8Array): string | undefined {
  if (value.byteLength < 2 || readU16(value, 0) !== value.byteLength - 2) throw new Error("invalid TLS SNI extension");
  let offset = 2;
  let hostname: string | undefined;
  while (offset < value.byteLength) {
    if (offset + 3 > value.byteLength) throw new Error("truncated TLS SNI name");
    const type = value[offset]!;
    const length = readU16(value, offset + 1);
    offset += 3;
    if (offset + length > value.byteLength) throw new Error("truncated TLS SNI hostname");
    if (type === 0) {
      if (hostname !== undefined) throw new Error("duplicate TLS host_name SNI");
      hostname = new TextDecoder("ascii", { fatal: true }).decode(value.subarray(offset, offset + length)).toLowerCase();
      if (!hostname || /[\u0000/]/.test(hostname)) throw new Error("invalid TLS SNI hostname");
    }
    offset += length;
  }
  return hostname;
}

function parseAlpn(value: Uint8Array): string[] {
  if (value.byteLength < 2 || readU16(value, 0) !== value.byteLength - 2) throw new Error("invalid TLS ALPN extension");
  const protocols: string[] = [];
  let offset = 2;
  while (offset < value.byteLength) {
    const length = value[offset++]!;
    if (length === 0 || offset + length > value.byteLength) throw new Error("invalid TLS ALPN value");
    protocols.push(new TextDecoder("ascii", { fatal: true }).decode(value.subarray(offset, offset + length)));
    offset += length;
  }
  return protocols;
}

function skipVector16(data: Uint8Array, offset: number, label: string): number {
  if (offset + 2 > data.byteLength) throw new Error(`truncated TLS ${label}`);
  const length = readU16(data, offset);
  const end = offset + 2 + length;
  if (end > data.byteLength) throw new Error(`truncated TLS ${label}`);
  return end;
}
function readU16(data: Uint8Array, offset: number): number {
  if (offset + 2 > data.byteLength) throw new Error("truncated binary field");
  return (data[offset]! << 8) | data[offset + 1]!;
}
function readU24(data: Uint8Array, offset: number): number {
  if (offset + 3 > data.byteLength) throw new Error("truncated binary field");
  return (data[offset]! << 16) | (data[offset + 1]! << 8) | data[offset + 2]!;
}
function concat(parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.byteLength; }
  return output;
}
function normalize(host: string): string { return host.toLowerCase().replace(/\.$/, ""); }
