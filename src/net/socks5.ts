import { formatEndpoint, type Endpoint } from "../protocol/endpoint.ts";

export type SocksGreetingResult = { status: "incomplete" } | { status: "ok"; consumed: number };
export type SocksRequestResult = { status: "incomplete" } | { status: "ok"; consumed: number; endpoint: Endpoint };

export function parseSocksGreeting(data: Uint8Array): SocksGreetingResult {
  if (data.byteLength < 2) return { status: "incomplete" };
  if (data[0] !== 5) throw new Error("only SOCKS5 is supported");
  const methods = data[1]!;
  if (data.byteLength < 2 + methods) return { status: "incomplete" };
  if (!data.subarray(2, 2 + methods).includes(0)) throw new Error("SOCKS5 client does not offer no-authentication mode");
  return { status: "ok", consumed: 2 + methods };
}

export function parseSocksConnect(data: Uint8Array): SocksRequestResult {
  if (data.byteLength < 4) return { status: "incomplete" };
  if (data[0] !== 5 || data[1] !== 1 || data[2] !== 0) throw new Error("only SOCKS5 CONNECT is supported");
  const type = data[3]!;
  let offset = 4;
  let host: string;
  if (type === 1) {
    if (data.byteLength < offset + 4 + 2) return { status: "incomplete" };
    host = [...data.subarray(offset, offset + 4)].join(".");
    offset += 4;
  } else if (type === 3) {
    if (data.byteLength < offset + 1) return { status: "incomplete" };
    const length = data[offset++]!;
    if (length === 0) throw new Error("empty SOCKS5 domain");
    if (data.byteLength < offset + length + 2) return { status: "incomplete" };
    host = new TextDecoder("ascii", { fatal: true }).decode(data.subarray(offset, offset + length)).toLowerCase();
    offset += length;
  } else if (type === 4) {
    if (data.byteLength < offset + 16 + 2) return { status: "incomplete" };
    const words: string[] = [];
    for (let index = 0; index < 16; index += 2) words.push(((data[offset + index]! << 8) | data[offset + index + 1]!).toString(16));
    host = words.join(":");
    offset += 16;
  } else {
    throw new Error("unsupported SOCKS5 address type");
  }
  const port = (data[offset]! << 8) | data[offset + 1]!;
  if (port === 0) throw new Error("invalid SOCKS5 destination port");
  offset += 2;
  return { status: "ok", consumed: offset, endpoint: { host, port } };
}

export function socksReply(code: number): Uint8Array {
  return Uint8Array.from([5, code & 0xff, 0, 1, 0, 0, 0, 0, 0, 0]);
}

export function describeSocksEndpoint(endpoint: Endpoint): string {
  return formatEndpoint(endpoint);
}
