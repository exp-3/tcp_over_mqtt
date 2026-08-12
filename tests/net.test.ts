import { describe, expect, test } from "bun:test";
import { assertEndpointAllowed, hostMatches, isProhibitedAddress } from "../src/net/access.ts";
import { assertHttpAuthority, inspectHttpRequest } from "../src/net/http-inspector.ts";
import { assertTlsIdentity, inspectTlsClientHello } from "../src/net/tls-client-hello.ts";
import { parseSocksConnect, parseSocksGreeting } from "../src/net/socks5.ts";

describe("access policy", () => {
  test("matches exact and a single wildcard suffix", () => {
    expect(hostMatches("*.example.com", "api.example.com")).toBeTrue();
    expect(hostMatches("*.example.com", "example.com")).toBeFalse();
    expect(hostMatches("*.example.com", "a.b.example.com")).toBeTrue();
    expect(hostMatches("example.com", "example.com.")).toBeTrue();
  });
  test("rejects common private and special address classes", () => {
    expect(isProhibitedAddress("127.0.0.1")).toBeTrue();
    expect(isProhibitedAddress("10.0.0.1")).toBeTrue();
    expect(isProhibitedAddress("169.254.1.1")).toBeTrue();
    expect(isProhibitedAddress("::1")).toBeTrue();
    expect(isProhibitedAddress("fc00::1")).toBeTrue();
    expect(isProhibitedAddress("8.8.8.8")).toBeFalse();
  });
  test("allows empty lists and enforces non-empty lists", () => {
    expect(() => assertEndpointAllowed({ host: "anything.example", port: 1 }, { allowedHosts: [], allowedPorts: [], denyPrivateNetworks: false })).not.toThrow();
    expect(() => assertEndpointAllowed({ host: "blocked.example", port: 443 }, { allowedHosts: ["allowed.example"], allowedPorts: [443], denyPrivateNetworks: false })).toThrow(/not allowed/);
  });
});

describe("HTTP first-flight inspector", () => {
  test("parses Host and validates it against endpoint", () => {
    const bytes = new TextEncoder().encode("POST /v1?a=1 HTTP/1.1\r\nHost: api.example.com:8080\r\nContent-Length: 3\r\n\r\nxyz");
    const result = inspectHttpRequest(bytes, 4096);
    expect(result.status).toBe("complete");
    if (result.status === "complete") {
      expect(result.info.host).toBe("api.example.com");
      expect(result.info.port).toBe(8080);
      expect(assertHttpAuthority(result.info, { host: "api.example.com", port: 8080 }, { requireHost: true, requireEndpointHostMatch: true })).toEqual({ host: "api.example.com", port: 8080 });
    }
  });
  test("waits for complete headers", () => {
    expect(inspectHttpRequest(new TextEncoder().encode("GET / HTTP/1.1\r\nHost: a"), 4096)).toEqual({ status: "incomplete" });
  });
});

describe("SOCKS5 parser", () => {
  test("handles no-auth greeting and CONNECT domain request", () => {
    expect(parseSocksGreeting(Uint8Array.from([5, 1, 0]))).toEqual({ status: "ok", consumed: 3 });
    const request = Uint8Array.from([5, 1, 0, 3, 11, ...new TextEncoder().encode("example.com"), 1, 187]);
    expect(parseSocksConnect(request)).toEqual({ status: "ok", consumed: request.byteLength, endpoint: { host: "example.com", port: 443 } });
  });
});

describe("TLS ClientHello inspector", () => {
  test("reads SNI and detects ECH extension", () => {
    const bytes = buildClientHello("api.example.com", true);
    const result = inspectTlsClientHello(bytes, 4096);
    expect(result.status).toBe("complete");
    if (result.status === "complete") {
      expect(result.info.sni).toBe("api.example.com");
      expect(result.info.ech).toBeTrue();
      expect(() => assertTlsIdentity(result.info, { host: "api.example.com", port: 443 }, {
        requireSni: true, requireEndpointSniMatch: true, allowEch: false, allowedEchPublicNames: [], legacySsl: "reject",
      })).toThrow(/ECH/);
      expect(() => assertTlsIdentity(result.info, { host: "api.example.com", port: 443 }, {
        requireSni: true, requireEndpointSniMatch: true, allowEch: true, allowedEchPublicNames: ["api.example.com"], legacySsl: "reject",
      })).not.toThrow();
    }
  });
});

function buildClientHello(host: string, ech: boolean): Uint8Array {
  const hostBytes = new TextEncoder().encode(host);
  const sni = Uint8Array.from([0, hostBytes.byteLength + 3, 0, 0, hostBytes.byteLength, ...hostBytes]);
  const sniExtension = Uint8Array.from([0, 0, 0, sni.byteLength, ...sni]);
  const echExtension = ech ? Uint8Array.from([0xfe, 0x0d, 0, 0]) : new Uint8Array();
  const body = Uint8Array.from([
    0x03, 0x03, ...new Uint8Array(32),
    0,
    0, 2, 0x13, 1,
    1, 0,
    0, sniExtension.byteLength + echExtension.byteLength,
    ...sniExtension, ...echExtension,
  ]);
  const handshake = Uint8Array.from([1, (body.byteLength >>> 16) & 255, (body.byteLength >>> 8) & 255, body.byteLength & 255, ...body]);
  return Uint8Array.from([22, 3, 1, (handshake.byteLength >>> 8) & 255, handshake.byteLength & 255, ...handshake]);
}
