import { parseEndpoint, type Endpoint } from "../protocol/endpoint.ts";

export interface HttpRequestInfo {
  method: string;
  target: string;
  version: string;
  host?: string;
  port?: number;
  headerBytes: number;
}

export type HttpInspection = { status: "incomplete" } | { status: "complete"; info: HttpRequestInfo };

export function inspectHttpRequest(data: Uint8Array, maxBytes: number): HttpInspection {
  if (data.byteLength > maxBytes) throw new Error(`HTTP request header exceeds ${maxBytes} bytes`);
  const end = findHeaderEnd(data);
  if (end < 0) return { status: "incomplete" };
  const headerBytes = end + 4;
  const text = new TextDecoder("latin1").decode(data.subarray(0, end));
  const lines = text.split("\r\n");
  const requestLine = lines.shift();
  if (!requestLine) throw new Error("empty HTTP request line");
  const match = /^([!#$%&'*+.^_`|~0-9A-Za-z-]+)\s+(\S+)\s+(HTTP\/1\.[01])$/.exec(requestLine);
  if (!match) throw new Error("invalid HTTP/1.x request line");
  const method = match[1]!;
  const target = match[2]!;
  const version = match[3]!;
  let hostHeader: string | undefined;
  for (const line of lines) {
    if (/^[ \t]/.test(line)) throw new Error("obsolete folded HTTP headers are not accepted");
    const colon = line.indexOf(":");
    if (colon <= 0) throw new Error("malformed HTTP header line");
    const name = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (name === "host") {
      if (hostHeader !== undefined) throw new Error("duplicate HTTP Host header");
      hostHeader = value;
    }
  }

  const authority = authorityFromTarget(method, target) ?? (hostHeader ? parseAuthority(hostHeader, 80) : undefined);
  return {
    status: "complete",
    info: {
      method,
      target,
      version,
      ...(authority ? { host: authority.host, port: authority.port } : {}),
      headerBytes,
    },
  };
}

export function assertHttpAuthority(
  info: HttpRequestInfo,
  endpoint: Endpoint,
  options: { requireHost: boolean; requireEndpointHostMatch: boolean },
): Endpoint | undefined {
  if (!info.host || !info.port) {
    if (options.requireHost) throw new Error("HTTP request does not contain a usable Host authority");
    return undefined;
  }
  const authority = { host: info.host, port: info.port };
  if (options.requireEndpointHostMatch) {
    if (normalize(endpoint.host) !== normalize(authority.host) || endpoint.port !== authority.port) {
      throw new Error(`HTTP Host '${authority.host}:${authority.port}' does not match endpoint '${endpoint.host}:${endpoint.port}'`);
    }
  }
  return authority;
}

function authorityFromTarget(method: string, target: string): Endpoint | undefined {
  if (method.toUpperCase() === "CONNECT") return parseAuthority(target, 443);
  if (/^https?:\/\//i.test(target)) {
    let url: URL;
    try { url = new URL(target); } catch { throw new Error("invalid absolute HTTP request target"); }
    return { host: url.hostname.toLowerCase(), port: url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80 };
  }
  return undefined;
}

function parseAuthority(value: string, defaultPort: number): Endpoint {
  const trimmed = value.trim();
  if (trimmed.startsWith("[")) {
    if (trimmed.includes("]:")) return parseEndpoint(trimmed);
    const close = trimmed.indexOf("]");
    if (close !== trimmed.length - 1) throw new Error("invalid bracketed HTTP authority");
    return { host: trimmed.slice(1, -1).toLowerCase(), port: defaultPort };
  }
  const colonCount = [...trimmed].filter((char) => char === ":").length;
  if (colonCount === 0) return { host: trimmed.toLowerCase(), port: defaultPort };
  if (colonCount === 1) return parseEndpoint(trimmed);
  throw new Error("IPv6 HTTP authority must use brackets");
}

function findHeaderEnd(data: Uint8Array): number {
  for (let index = 0; index <= data.byteLength - 4; index++) {
    if (data[index] === 13 && data[index + 1] === 10 && data[index + 2] === 13 && data[index + 3] === 10) return index;
  }
  return -1;
}

function normalize(host: string): string {
  return host.toLowerCase().replace(/\.$/, "");
}
