import { isIP } from "node:net";
import { lookup } from "node:dns/promises";
import type { AccessConfig } from "../types.ts";
import type { Endpoint } from "../protocol/endpoint.ts";

export interface AuthorizedEndpoint extends Endpoint {
  connectHost: string;
  resolvedAddresses: string[];
}

export function normalizeHost(host: string): string {
  const normalized = host.trim().toLowerCase().replace(/\.$/, "");
  if (!normalized) throw new Error("host cannot be empty");
  return normalized;
}

export function hostMatches(pattern: string, host: string): boolean {
  const expected = normalizeHost(pattern);
  const actual = normalizeHost(host);
  if (!expected.startsWith("*.")) return expected === actual;
  const suffix = expected.slice(2);
  if (!suffix || !actual.endsWith(`.${suffix}`)) return false;
  return actual.slice(0, -(suffix.length + 1)).length > 0;
}

export function assertEndpointAllowed(endpoint: Endpoint, access: AccessConfig, label = "endpoint"): void {
  const host = normalizeHost(endpoint.host);
  if (access.allowedHosts.length > 0 && !access.allowedHosts.some((pattern) => hostMatches(pattern, host))) {
    throw new Error(`${label} host '${host}' is not allowed`);
  }
  if (access.allowedPorts.length > 0 && !access.allowedPorts.includes(endpoint.port)) {
    throw new Error(`${label} port '${endpoint.port}' is not allowed`);
  }
}

export async function authorizeEndpoint(
  endpoint: Endpoint,
  access: AccessConfig,
  label = "endpoint",
): Promise<AuthorizedEndpoint> {
  assertEndpointAllowed(endpoint, access, label);
  const host = normalizeHost(endpoint.host);
  let addresses: string[];
  if (isIP(host)) {
    addresses = [host];
  } else {
    const answers = await lookup(host, { all: true, verbatim: true });
    addresses = [...new Set(answers.map((answer) => answer.address))];
    if (addresses.length === 0) throw new Error(`${label} host '${host}' did not resolve`);
  }
  if (access.denyPrivateNetworks) {
    const prohibited = addresses.find(isProhibitedAddress);
    if (prohibited) throw new Error(`${label} host '${host}' resolves to prohibited address '${prohibited}'`);
  }
  return { host, port: endpoint.port, connectHost: addresses[0]!, resolvedAddresses: addresses };
}

export function isProhibitedAddress(address: string): boolean {
  const version = isIP(address);
  if (version === 4) return isProhibitedIpv4(address);
  if (version === 6) return isProhibitedIpv6(address);
  return true;
}

function isProhibitedIpv4(address: string): boolean {
  const octets = address.split(".").map(Number);
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b] = octets as [number, number, number, number];
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

function isProhibitedIpv6(address: string): boolean {
  const lower = address.toLowerCase().split("%")[0]!;
  if (lower === "::" || lower === "::1") return true;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
  if (mapped) return isProhibitedIpv4(mapped[1]!);
  const first = firstIpv6Word(lower);
  return (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80 || (first & 0xff00) === 0xff00;
}

function firstIpv6Word(address: string): number {
  const first = address.split(":", 1)[0];
  if (!first) return 0;
  const parsed = Number.parseInt(first, 16);
  return Number.isFinite(parsed) ? parsed : 0;
}
