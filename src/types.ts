export const PROTOCOLS = ["tcp", "tls", "http", "socks"] as const;
export type TunnelProtocol = (typeof PROTOCOLS)[number];

export const RECORD_TYPES = [
  "OPEN",
  "OPEN_OK",
  "OPEN_ERROR",
  "DATA",
  "FIN",
  "CLOSE",
  "CANCEL",
  "WINDOW_UPDATE",
  "ERROR",
  "PING",
  "PONG",
] as const;
export type RecordType = (typeof RECORD_TYPES)[number];

export type Direction = "c2s" | "s2c";
export type ArchiveMode = "tar" | "tgz";
export type ProtectionMode = "plain" | "aead" | "rc4";
export type HttpOriginProtocol = "http" | "https";

export interface TunnelRecord {
  tunnelId: string;
  sequence: bigint;
  type: RecordType;
  protocol?: TunnelProtocol;
  endpoint?: string;
  flags?: string[];
  errorCode?: string;
  errorMessage?: string;
  windowBytes?: number;
  data?: Uint8Array;
}

export interface TunnelBatch {
  id: string;
  records: TunnelRecord[];
}

export interface TopicParts {
  topicPrefix: string;
  direction: Direction;
  toNodeId: string;
  fromNodeId: string;
  archive: ArchiveMode;
  protection: ProtectionMode;
}

export interface ProtocolSwitches {
  tcp: boolean;
  tls: boolean;
  http: boolean;
  socks: boolean;
}

export interface MqttConfig {
  url: string;
  clientId: string;
  topicPrefix: string;
  protocolVersion: 4 | 5;
  qos: 0 | 1 | 2;
  username?: string;
  password?: string;
  usernameEnv?: string;
  passwordEnv?: string;
  rejectUnauthorized: boolean;
}

export interface BatchConfig {
  archive: ArchiveMode;
  protection: ProtectionMode;
  maxBatchBytes: number;
  maxRecordsPerBatch: number;
  maxDelayMs: number;
  minPublishIntervalMs: number;
  maxQueuedRecords: number;
  maxDecompressedBytes: number;
  maxCompressionRatio: number;
  key?: string;
  keyEnv?: string;
}

export interface AccessConfig {
  allowedHosts: string[];
  allowedPorts: number[];
  denyPrivateNetworks: boolean;
}

export interface HttpConfig extends AccessConfig {
  requestHeaderMaxBytes: number;
  requestHeaderTimeoutMs: number;
  responseHeaderMaxBytes: number;
  responseHeaderTimeoutMs: number;
}

export interface TlsConfig extends AccessConfig {
  requireSni: boolean;
  requireEndpointSniMatch: boolean;
  allowEch: boolean;
  allowedEchPublicNames: string[];
  legacySsl: "reject" | "static-route-only";
  clientHelloMaxBytes: number;
  clientHelloTimeoutMs: number;
}

export interface SocksConfig extends AccessConfig {
  connectTimeoutMs: number;
}

export interface TunnelConfig {
  maxConcurrentTunnels: number;
  maxBufferedBytesPerTunnel: number;
  idleTimeoutMs: number;
  connectTimeoutMs: number;
}

export interface ListenerConfig {
  name: string;
  type: TunnelProtocol;
  listenHost: string;
  listenPort: number;
  toNodeId: string;
  targetHost?: string;
  targetPort?: number;
  originHost?: string;
  originPort?: number;
  originProtocol?: HttpOriginProtocol;
  originRequestHost?: string;
}

export interface AppConfig {
  role: "connector" | "server";
  nodeId: string;
  mqtt: MqttConfig;
  protocols: ProtocolSwitches;
  batch: BatchConfig;
  tunnel: TunnelConfig;
  egress: AccessConfig;
  http: HttpConfig;
  tls: TlsConfig;
  socks: SocksConfig;
  listeners: ListenerConfig[];
}
