import { parseEndpoint } from "../protocol/endpoint.ts";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("latin1");
const HOP_BY_HOP = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"]);

export interface HttpHead {
  startLine: string;
  headers: Array<{ name: string; value: string }>;
  headerBytes: number;
}

export interface HttpMessageInfo extends HttpHead {
  bodyKind: "none" | "content-length" | "chunked" | "close";
  contentLength?: number;
  upgradeWebSocket: boolean;
  connectionClose: boolean;
}

export type HeadInspection = { status: "incomplete" } | { status: "complete"; info: HttpMessageInfo };

export function inspectHttpHead(data: Uint8Array, maxBytes: number, kind: "request" | "response"): HeadInspection {
  if (data.byteLength > maxBytes) throw new Error(`HTTP ${kind} header exceeds ${maxBytes} bytes`);
  const end = findHeaderEnd(data);
  if (end < 0) return { status: "incomplete" };
  const text = textDecoder.decode(data.subarray(0, end));
  const lines = text.split("\r\n");
  const startLine = lines.shift();
  if (!startLine) throw new Error(`empty HTTP ${kind} start line`);
  if (kind === "request") {
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+\s+\S+\s+HTTP\/1\.[01]$/.test(startLine)) throw new Error("invalid HTTP/1.x request line");
  } else if (!/^HTTP\/1\.[01]\s+[0-9]{3}(?:\s.*)?$/.test(startLine)) {
    throw new Error("invalid HTTP/1.x response status line");
  }
  const headers: Array<{ name: string; value: string }> = [];
  let contentLength: number | undefined;
  let transferEncoding: string | undefined;
  let connection = "";
  let upgrade = "";
  for (const line of lines) {
    if (/^[ \t]/.test(line)) throw new Error("obsolete folded HTTP headers are not accepted");
    const colon = line.indexOf(":");
    if (colon <= 0) throw new Error("malformed HTTP header line");
    const name = line.slice(0, colon).trim();
    const value = line.slice(colon + 1).trim();
    const lower = name.toLowerCase();
    if (lower === "content-length") {
      const parsed = Number(value);
      if (!/^\d+$/.test(value) || !Number.isSafeInteger(parsed)) throw new Error("invalid HTTP Content-Length");
      if (contentLength !== undefined && contentLength !== parsed) throw new Error("conflicting HTTP Content-Length headers");
      contentLength = parsed;
    }
    if (lower === "transfer-encoding") transferEncoding = value.toLowerCase();
    if (lower === "connection") connection = value.toLowerCase();
    if (lower === "upgrade") upgrade = value.toLowerCase();
    headers.push({ name, value });
  }
  if (transferEncoding && contentLength !== undefined) throw new Error("HTTP request cannot contain both Transfer-Encoding and Content-Length");
  const status = kind === "response" ? Number(startLine.split(" ")[1]) : undefined;
  const noBody = kind === "response" && (status === 101 || status === 204 || status === 304);
  const bodyKind: HttpMessageInfo["bodyKind"] = noBody ? "none" : transferEncoding ? (transferEncoding === "chunked" ? "chunked" : (() => { throw new Error("unsupported HTTP Transfer-Encoding"); })()) : contentLength !== undefined ? (contentLength === 0 ? "none" : "content-length") : kind === "response" ? "close" : "none";
  return { status: "complete", info: { startLine, headers, headerBytes: end + 4, bodyKind, ...(contentLength !== undefined ? { contentLength } : {}), upgradeWebSocket: connection.split(",").some((x) => x.trim() === "upgrade") && upgrade === "websocket", connectionClose: connection.split(",").some((x) => x.trim() === "close") } };
}

export function rewriteRequestHead(head: HttpMessageInfo, originRequestHost: string): Uint8Array {
  const [method, target, version] = head.startLine.split(" ");
  if (!method || !target || !version) throw new Error("invalid HTTP request line");
  if (method.toUpperCase() === "CONNECT") throw new Error("HTTP CONNECT is not supported by reverse proxy mode");
  let rewrittenTarget = target;
  if (/^https?:\/\//i.test(target)) {
    const url = new URL(target);
    rewrittenTarget = `${url.pathname || "/"}${url.search}`;
  }
  if (target === "*") throw new Error("HTTP asterisk-form requests are not supported");
  const connectionTokens = new Set(head.headers.filter((header) => header.name.toLowerCase() === "connection").flatMap((header) => header.value.toLowerCase().split(",").map((value) => value.trim())));
  const lines = [`${method} ${rewrittenTarget} ${version}`, `Host: ${originRequestHost}`];
  for (const header of head.headers) {
    const lower = header.name.toLowerCase();
    // A chunked body is forwarded verbatim, so its framing header must accompany it.
    if (lower === "host" || (HOP_BY_HOP.has(lower) && lower !== "transfer-encoding" && lower !== "trailer") || connectionTokens.has(lower)) continue;
    lines.push(`${header.name}: ${header.value}`);
  }
  if (head.upgradeWebSocket) { lines.push("Connection: Upgrade", "Upgrade: websocket"); }
  return textEncoder.encode(`${lines.join("\r\n")}\r\n\r\n`);
}

export function defaultOriginRequestHost(host: string, port: number, protocol: "http" | "https"): string {
  const formatted = host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
  return port === (protocol === "https" ? 443 : 80) ? formatted : `${formatted}:${port}`;
}

export function requestAuthority(head: HttpMessageInfo): { host: string; port: number } | undefined {
  const absoluteTarget = head.startLine.split(" ")[1];
  if (absoluteTarget && /^https?:\/\//i.test(absoluteTarget)) {
    const url = new URL(absoluteTarget);
    return { host: url.hostname, port: url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80 };
  }
  const host = head.headers.find((header) => header.name.toLowerCase() === "host")?.value;
  if (!host) return undefined;
  return parseEndpoint(host.includes(":") || host.startsWith("[") ? host : `${host}:80`);
}

function findHeaderEnd(data: Uint8Array): number {
  for (let index = 0; index <= data.byteLength - 4; index++) if (data[index] === 13 && data[index + 1] === 10 && data[index + 2] === 13 && data[index + 3] === 10) return index;
  return -1;
}

/** Incremental parser for a chunked HTTP body. It tracks framing only; callers retain and forward the original bytes. */
export class ChunkedBodyTracker {
  private phase: "size" | "data" | "data-cr" | "data-lf" | "trailers" = "size";
  private line = "";
  private remaining = 0;

  /** Returns the number of bytes belonging to this chunked body from `data`, and whether it completed. */
  consume(data: Uint8Array): { consumed: number; complete: boolean } {
    for (let index = 0; index < data.byteLength; index++) {
      const byte = data[index]!;
      if (this.phase === "size" || this.phase === "trailers") {
        this.line += String.fromCharCode(byte);
        if (this.line.length > 16_384) throw new Error("HTTP chunked framing line is too large");
        if (!this.line.endsWith("\r\n")) continue;
        const line = this.line.slice(0, -2);
        this.line = "";
        if (this.phase === "trailers") {
          if (line === "") return { consumed: index + 1, complete: true };
          continue;
        }
        const sizeText = line.split(";", 1)[0]!;
        if (!/^[0-9a-fA-F]+$/.test(sizeText)) throw new Error("invalid HTTP chunk size");
        const size = Number.parseInt(sizeText, 16);
        if (!Number.isSafeInteger(size)) throw new Error("HTTP chunk size exceeds safe integer range");
        if (size === 0) this.phase = "trailers";
        else { this.remaining = size; this.phase = "data"; }
        continue;
      }
      if (this.phase === "data") {
        this.remaining -= 1;
        if (this.remaining === 0) this.phase = "data-cr";
        continue;
      }
      if (this.phase === "data-cr") {
        if (byte !== 13) throw new Error("malformed HTTP chunk terminator");
        this.phase = "data-lf";
        continue;
      }
      if (byte !== 10) throw new Error("malformed HTTP chunk terminator");
      this.phase = "size";
    }
    return { consumed: data.byteLength, complete: false };
  }
}
