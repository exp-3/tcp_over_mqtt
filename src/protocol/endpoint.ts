export interface Endpoint {
  host: string;
  port: number;
}

export function formatEndpoint(endpoint: Endpoint): string {
  const host = endpoint.host.includes(":") && !endpoint.host.startsWith("[") ? `[${endpoint.host}]` : endpoint.host;
  return `${host}:${endpoint.port}`;
}

export function parseEndpoint(input: string): Endpoint {
  if (input.length === 0 || input.length > 512) throw new Error("invalid empty or oversized endpoint");
  let host: string;
  let portText: string;
  if (input.startsWith("[")) {
    const close = input.indexOf("]");
    if (close < 2 || input[close + 1] !== ":") throw new Error(`invalid IPv6 endpoint '${input}'`);
    host = input.slice(1, close);
    portText = input.slice(close + 2);
  } else {
    const colon = input.lastIndexOf(":");
    if (colon <= 0) throw new Error(`endpoint '${input}' must contain host:port`);
    host = input.slice(0, colon);
    portText = input.slice(colon + 1);
    if (host.includes(":")) throw new Error("IPv6 endpoints must use [address]:port syntax");
  }
  const port = Number(portText);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`invalid endpoint port '${portText}'`);
  if (/[/+#\s\u0000-\u001f\u007f]/u.test(host)) throw new Error("endpoint host contains prohibited characters");
  if (host.length > 253) throw new Error("endpoint host is too long");
  return { host: host.toLowerCase().replace(/\.$/, ""), port };
}
