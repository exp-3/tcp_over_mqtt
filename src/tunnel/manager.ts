import { randomUUID } from "node:crypto";
import { assertEndpointAllowed, authorizeEndpoint } from "../net/access.ts";
import { assertHttpAuthority, inspectHttpRequest } from "../net/http-inspector.ts";
import { parseSocksConnect, parseSocksGreeting, socksReply } from "../net/socks5.ts";
import { assertTlsIdentity, inspectTlsClientHello } from "../net/tls-client-hello.ts";
import { formatEndpoint, parseEndpoint, type Endpoint } from "../protocol/endpoint.ts";
import type { AppConfig, Direction, ListenerConfig, TunnelBatch, TunnelProtocol, TunnelRecord } from "../types.ts";
import type { RecordBatcher } from "./batcher.ts";

export interface RelaySocket {
  write(data: Uint8Array): number;
  end(data?: Uint8Array): number | void;
  terminate(): void;
}

interface TunnelState {
  key: string;
  tunnelId: string;
  peerNodeId: string;
  protocol: TunnelProtocol;
  endpoint: Endpoint;
  outgoingDirection: Direction;
  nextSend: bigint;
  nextReceive: bigint;
  awaitingOpen: boolean;
  connecting: boolean;
  connected: boolean;
  socket?: RelaySocket;
  pendingSocketWrites: Uint8Array[];
  pendingFin: boolean;
  inspection: Uint8Array[];
  inspectionBytes: number;
  inspectionTimer?: ReturnType<typeof setTimeout>;
  idleTimer?: ReturnType<typeof setTimeout>;
  socketEnded: boolean;
  remoteEnded: boolean;
  socksLocal: boolean;
}

interface LocalAttachment {
  listener: ListenerConfig;
  socket: RelaySocket;
  state?: TunnelState;
  socksBuffer: Uint8Array;
  socksGreetingDone: boolean;
  closed: boolean;
}

/** Owns local and remote tunnel sockets, sequencing, first-flight policy checks, and egress dialing. */
export class TunnelManager {
  private readonly tunnels = new Map<string, TunnelState>();
  private readonly attachments = new Map<RelaySocket, LocalAttachment>();
  private readonly localDirection: Direction;

  public constructor(private readonly config: AppConfig, private readonly batcher: RecordBatcher) {
    this.localDirection = config.role === "connector" ? "c2s" : "s2c";
  }

  attachLocalSocket(socket: RelaySocket, listener: ListenerConfig): void {
    const attachment: LocalAttachment = { listener, socket, socksBuffer: new Uint8Array(), socksGreetingDone: false, closed: false };
    this.attachments.set(socket, attachment);
    if (listener.type !== "socks") {
      const endpoint = { host: listener.targetHost!, port: listener.targetPort! };
      attachment.state = this.createLocalTunnel(socket, listener, endpoint, new Uint8Array());
    }
  }

  localData(socket: RelaySocket, chunk: Uint8Array): void {
    const attachment = this.attachments.get(socket);
    if (!attachment || attachment.closed) return;
    try {
      if (attachment.state) {
        this.sendData(attachment.state, chunk);
        return;
      }
      this.consumeSocks(attachment, chunk);
    } catch (error) {
      this.failLocalAttachment(attachment, asError(error));
    }
  }

  localEnd(socket: RelaySocket): void {
    const attachment = this.attachments.get(socket);
    if (!attachment) return;
    attachment.closed = true;
    if (attachment.state) this.sendFin(attachment.state);
  }

  localError(socket: RelaySocket, error: Error): void {
    const attachment = this.attachments.get(socket);
    if (!attachment) return;
    attachment.closed = true;
    if (attachment.state) this.closeState(attachment.state, "LOCAL_SOCKET_ERROR", error.message, true);
    this.attachments.delete(socket);
  }

  socketDrain(socket: RelaySocket): void {
    const attachment = this.attachments.get(socket);
    if (attachment?.state) this.flushSocket(attachment.state);
    for (const state of this.tunnels.values()) if (state.socket === socket) this.flushSocket(state);
  }

  async handleBatch(batch: TunnelBatch, context: { direction: Direction; fromNodeId: string }): Promise<void> {
    if (context.direction === this.localDirection) throw new Error(`unexpected inbound direction '${context.direction}' for ${this.config.role}`);
    for (const record of batch.records) {
      try {
        await this.handleRecord(record, context);
      } catch (error) {
        const message = asError(error).message;
        const existing = this.tunnels.get(tunnelKey(context.fromNodeId, record.tunnelId));
        if (existing) {
          this.closeState(existing, "PROTOCOL_ERROR", message, true);
        } else if (record.type === "OPEN") {
          this.batcher.enqueue({
            direction: opposite(context.direction),
            toNodeId: context.fromNodeId,
            record: { tunnelId: record.tunnelId, sequence: 0n, type: "OPEN_ERROR", errorCode: "OPEN_REJECTED", errorMessage: message },
          });
        }
      }
    }
  }

  close(): void {
    for (const state of [...this.tunnels.values()]) this.closeState(state, "SHUTDOWN", "application is shutting down", false);
    this.attachments.clear();
  }

  private createLocalTunnel(socket: RelaySocket, listener: ListenerConfig, endpoint: Endpoint, initialData: Uint8Array): TunnelState {
    const tunnelId = randomUUID();
    const state: TunnelState = {
      key: tunnelKey(listener.toNodeId, tunnelId),
      tunnelId,
      peerNodeId: listener.toNodeId,
      protocol: listener.type,
      endpoint,
      outgoingDirection: this.localDirection,
      nextSend: 1n,
      nextReceive: 1n,
      awaitingOpen: true,
      connecting: false,
      connected: false,
      socket,
      pendingSocketWrites: [],
      pendingFin: false,
      inspection: [],
      inspectionBytes: 0,
      socketEnded: false,
      remoteEnded: false,
      socksLocal: listener.type === "socks",
    };
    this.tunnels.set(state.key, state);
    this.touch(state);
    const inlineLimit = maxDataBytesPerRecord(this.config);
    const inlineData = initialData.byteLength > 0 && initialData.byteLength <= inlineLimit ? initialData : undefined;
    this.batcher.enqueue({
      direction: state.outgoingDirection,
      toNodeId: state.peerNodeId,
      record: { tunnelId, sequence: 0n, type: "OPEN", protocol: state.protocol, endpoint: formatEndpoint(endpoint), ...(inlineData ? { data: inlineData } : {}) },
    });
    if (initialData.byteLength > (inlineData?.byteLength ?? 0)) this.sendData(state, initialData);
    return state;
  }

  private consumeSocks(attachment: LocalAttachment, data: Uint8Array): void {
    attachment.socksBuffer = concat([attachment.socksBuffer, data]);
    if (!attachment.socksGreetingDone) {
      const greeting = parseSocksGreeting(attachment.socksBuffer);
      if (greeting.status === "incomplete") return;
      attachment.socket.write(Uint8Array.from([5, 0]));
      attachment.socksBuffer = attachment.socksBuffer.slice(greeting.consumed);
      attachment.socksGreetingDone = true;
    }
    if (!attachment.state) {
      const request = parseSocksConnect(attachment.socksBuffer);
      if (request.status === "incomplete") return;
      attachment.socksBuffer = attachment.socksBuffer.slice(request.consumed);
      attachment.state = this.createLocalTunnel(attachment.socket, attachment.listener, request.endpoint, attachment.socksBuffer);
      attachment.socksBuffer = new Uint8Array();
    }
    if (attachment.socksBuffer.byteLength && attachment.state) {
      this.sendData(attachment.state, attachment.socksBuffer);
      attachment.socksBuffer = new Uint8Array();
    }
  }

  private async handleRecord(record: TunnelRecord, context: { direction: Direction; fromNodeId: string }): Promise<void> {
    if (record.type === "OPEN") return this.handleOpen(record, context);
    const state = this.tunnels.get(tunnelKey(context.fromNodeId, record.tunnelId));
    if (!state) return;
    this.touch(state);
    if (record.type === "OPEN_OK" || record.type === "OPEN_ERROR") {
      if (!state.awaitingOpen || record.sequence !== 0n) return;
      state.awaitingOpen = false;
      if (record.type === "OPEN_ERROR") {
        this.failOpen(state, record.errorCode ?? "OPEN_ERROR", record.errorMessage ?? "remote peer rejected tunnel");
        return;
      }
      state.connected = true;
      if (state.socksLocal) this.writeSocket(state, socksReply(0));
      if (record.data) this.writeSocket(state, record.data);
      return;
    }
    if (!this.acceptSequence(state, record)) return;
    if (record.type === "DATA") {
      if (record.data?.byteLength) this.receivePayload(state, record.data);
      return;
    }
    if (record.type === "FIN") {
      state.remoteEnded = true;
      if (state.pendingSocketWrites.length > 0) state.pendingFin = true;
      else if (state.socket) state.socket.end();
      this.maybeDestroy(state);
      return;
    }
    if (record.type === "CLOSE" || record.type === "CANCEL") {
      this.closeState(state, "REMOTE_CLOSE", record.errorMessage ?? record.type, false);
      return;
    }
    if (record.type === "WINDOW_UPDATE" || record.type === "PING") {
      if (record.type === "PING") this.sendControl(state, "PONG");
      return;
    }
    if (record.type === "ERROR") {
      this.closeState(state, record.errorCode ?? "REMOTE_ERROR", record.errorMessage ?? "remote tunnel error", false);
    }
  }

  private async handleOpen(record: TunnelRecord, context: { direction: Direction; fromNodeId: string }): Promise<void> {
    if (record.sequence !== 0n || !record.protocol || !record.endpoint) throw new Error("invalid OPEN record");
    if (!this.config.protocols[record.protocol]) throw new Error(`protocol '${record.protocol}' is disabled`);
    const key = tunnelKey(context.fromNodeId, record.tunnelId);
    if (this.tunnels.has(key)) return;
    if (this.tunnels.size >= this.config.tunnel.maxConcurrentTunnels) throw new Error("maxConcurrentTunnels limit reached");
    const endpoint = parseEndpoint(record.endpoint);
    const state: TunnelState = {
      key,
      tunnelId: record.tunnelId,
      peerNodeId: context.fromNodeId,
      protocol: record.protocol,
      endpoint,
      outgoingDirection: opposite(context.direction),
      nextSend: 1n,
      nextReceive: 1n,
      awaitingOpen: false,
      connecting: false,
      connected: false,
      pendingSocketWrites: [],
      pendingFin: false,
      inspection: [],
      inspectionBytes: 0,
      socketEnded: false,
      remoteEnded: false,
      socksLocal: false,
    };
    this.tunnels.set(key, state);
    this.touch(state);
    if (record.data?.byteLength) this.receivePayload(state, record.data);
    this.startOrInspect(state);
  }

  private acceptSequence(state: TunnelState, record: TunnelRecord): boolean {
    if (record.sequence < state.nextReceive) return false;
    if (record.sequence !== state.nextReceive) throw new Error(`out-of-order record sequence ${record.sequence}; expected ${state.nextReceive}`);
    state.nextReceive += 1n;
    return true;
  }

  private receivePayload(state: TunnelState, data: Uint8Array): void {
    this.touch(state);
    if (!state.connected) {
      state.inspection.push(data);
      state.inspectionBytes += data.byteLength;
      const max = state.protocol === "http" ? this.config.http.requestHeaderMaxBytes : state.protocol === "tls" ? this.config.tls.clientHelloMaxBytes : this.config.tunnel.maxBufferedBytesPerTunnel;
      if (state.inspectionBytes > Math.min(max, this.config.tunnel.maxBufferedBytesPerTunnel)) throw new Error("pre-connect tunnel data exceeds configured limit");
      this.startOrInspect(state);
      return;
    }
    this.writeSocket(state, data);
  }

  private startOrInspect(state: TunnelState): void {
    if (state.connecting || state.connected) return;
    try {
      assertEndpointAllowed(state.endpoint, this.config.egress, "egress endpoint");
      if (state.protocol === "tcp") {
        void this.connectEgress(state);
        return;
      }
      if (state.protocol === "socks") {
        assertEndpointAllowed(state.endpoint, this.config.socks, "SOCKS endpoint");
        void this.connectEgress(state);
        return;
      }
      const initial = concat(state.inspection);
      if (state.protocol === "http") {
        const inspected = inspectHttpRequest(initial, this.config.http.requestHeaderMaxBytes);
        if (inspected.status === "incomplete") return this.armInspectionTimeout(state, this.config.http.requestHeaderTimeoutMs);
        const authority = assertHttpAuthority(inspected.info, state.endpoint, this.config.http);
        assertEndpointAllowed(state.endpoint, this.config.http, "HTTP endpoint");
        if (authority) assertEndpointAllowed(authority, this.config.http, "HTTP Host");
      } else {
        const inspected = inspectTlsClientHello(initial, this.config.tls.clientHelloMaxBytes);
        if (inspected.status === "incomplete") return this.armInspectionTimeout(state, this.config.tls.clientHelloTimeoutMs);
        assertTlsIdentity(inspected.info, state.endpoint, this.config.tls);
        assertEndpointAllowed(state.endpoint, this.config.tls, "TLS endpoint");
        if (inspected.info.sni && !inspected.info.ech) {
          assertEndpointAllowed({ host: inspected.info.sni, port: state.endpoint.port }, this.config.tls, "TLS SNI");
        }
      }
      void this.connectEgress(state);
    } catch (error) {
      this.closeState(state, "POLICY_REJECTED", asError(error).message, true);
    }
  }

  private armInspectionTimeout(state: TunnelState, timeoutMs: number): void {
    if (state.inspectionTimer) return;
    state.inspectionTimer = setTimeout(() => {
      delete state.inspectionTimer;
      this.closeState(state, "INSPECTION_TIMEOUT", "timed out waiting for protocol first flight", true);
    }, timeoutMs);
  }

  private async connectEgress(state: TunnelState): Promise<void> {
    if (state.connecting || state.connected) return;
    state.connecting = true;
    try {
      const policy = state.protocol === "http" ? this.config.http : state.protocol === "tls" ? this.config.tls : state.protocol === "socks" ? this.config.socks : this.config.egress;
      const authorized = await authorizeEndpoint(state.endpoint, {
        allowedHosts: [],
        allowedPorts: [],
        denyPrivateNetworks: this.config.egress.denyPrivateNetworks || policy.denyPrivateNetworks,
      }, "egress endpoint");
      const socket = await connectWithTimeout(authorized.connectHost, state.endpoint.port, this.config.tunnel.connectTimeoutMs, {
        open: () => undefined,
        data: (_socket, data) => this.egressData(state, new Uint8Array(data)),
        end: () => this.egressEnd(state),
        close: (_socket, error) => { if (error) this.egressError(state, error); },
        error: (_socket, error) => this.egressError(state, error),
        drain: () => this.flushSocket(state),
      });
      if (!this.tunnels.has(state.key)) { socket.terminate(); return; }
      state.socket = socket;
      state.connecting = false;
      state.connected = true;
      if (state.inspectionTimer) { clearTimeout(state.inspectionTimer); delete state.inspectionTimer; }
      this.batcher.enqueue({ direction: state.outgoingDirection, toNodeId: state.peerNodeId, record: { tunnelId: state.tunnelId, sequence: 0n, type: "OPEN_OK" } });
      const initial = concat(state.inspection);
      state.inspection = [];
      state.inspectionBytes = 0;
      if (initial.byteLength) this.writeSocket(state, initial);
    } catch (error) {
      state.connecting = false;
      this.closeState(state, "CONNECT_FAILED", asError(error).message, true);
    }
  }

  private egressData(state: TunnelState, data: Uint8Array): void { this.sendData(state, data); }
  private egressEnd(state: TunnelState): void {
    if (!this.tunnels.has(state.key)) return;
    this.sendFin(state);
    this.maybeDestroy(state);
  }
  private egressError(state: TunnelState, error: Error): void { this.closeState(state, "EGRESS_SOCKET_ERROR", error.message, true); }

  private sendData(state: TunnelState, data: Uint8Array): void {
    if (!this.tunnels.has(state.key) || state.socketEnded || data.byteLength === 0) return;
    this.touch(state);
    const maximum = maxDataBytesPerRecord(this.config);
    for (let offset = 0; offset < data.byteLength; offset += maximum) {
      const chunk = data.slice(offset, Math.min(offset + maximum, data.byteLength));
      this.batcher.enqueue({ direction: state.outgoingDirection, toNodeId: state.peerNodeId, record: { tunnelId: state.tunnelId, sequence: state.nextSend++, type: "DATA", data: chunk } });
    }
  }
  private sendFin(state: TunnelState): void {
    if (!this.tunnels.has(state.key) || state.socketEnded) return;
    state.socketEnded = true;
    this.batcher.enqueue({ direction: state.outgoingDirection, toNodeId: state.peerNodeId, record: { tunnelId: state.tunnelId, sequence: state.nextSend++, type: "FIN" } });
  }
  private sendControl(state: TunnelState, type: Extract<TunnelRecord["type"], "PONG">): void {
    this.batcher.enqueue({ direction: state.outgoingDirection, toNodeId: state.peerNodeId, record: { tunnelId: state.tunnelId, sequence: state.nextSend++, type } });
  }

  private writeSocket(state: TunnelState, data: Uint8Array): void {
    if (!state.socket || data.byteLength === 0) return;
    state.pendingSocketWrites.push(data);
    this.flushSocket(state);
  }
  private flushSocket(state: TunnelState): void {
    if (!state.socket) return;
    while (state.pendingSocketWrites.length > 0) {
      const chunk = state.pendingSocketWrites[0]!;
      const written = state.socket.write(chunk);
      if (written < 0) { this.closeState(state, "SOCKET_CLOSED", "socket closed while forwarding", false); return; }
      if (written < chunk.byteLength) {
        state.pendingSocketWrites[0] = chunk.slice(written);
        return;
      }
      state.pendingSocketWrites.shift();
    }
    if (state.pendingFin) { state.pendingFin = false; state.socket.end(); }
  }

  private failOpen(state: TunnelState, code: string, message: string): void {
    if (state.socksLocal) this.writeSocket(state, socksReply(5));
    this.closeState(state, code, message, false);
  }
  private failLocalAttachment(attachment: LocalAttachment, error: Error): void {
    if (attachment.listener.type === "socks") attachment.socket.write(socksReply(1));
    attachment.socket.terminate();
    attachment.closed = true;
  }

  private closeState(state: TunnelState, code: string, message: string, notifyPeer: boolean): void {
    if (!this.tunnels.delete(state.key)) return;
    if (state.inspectionTimer) clearTimeout(state.inspectionTimer);
    if (state.idleTimer) clearTimeout(state.idleTimer);
    if (notifyPeer) {
      const type = state.awaitingOpen || !state.connected ? "OPEN_ERROR" : "ERROR";
      const sequence = type === "OPEN_ERROR" ? 0n : state.nextSend++;
      this.batcher.enqueue({ direction: state.outgoingDirection, toNodeId: state.peerNodeId, record: { tunnelId: state.tunnelId, sequence, type, errorCode: code, errorMessage: message } });
    }
    if (state.socket) {
      state.socket.terminate();
      this.attachments.delete(state.socket);
    }
  }

  private maybeDestroy(state: TunnelState): void {
    if (state.socketEnded && state.remoteEnded) this.closeState(state, "FINISHED", "both directions finished", false);
  }
  private touch(state: TunnelState): void {
    if (state.idleTimer) clearTimeout(state.idleTimer);
    state.idleTimer = setTimeout(() => this.closeState(state, "IDLE_TIMEOUT", "tunnel idle timeout", true), this.config.tunnel.idleTimeoutMs);
  }
}

function maxDataBytesPerRecord(config: AppConfig): number {
  // TAR has a fixed 10 KiB minimum plus per-entry headers; preserve space for metadata and protection.
  return Math.max(1_024, config.batch.maxBatchBytes - 16_384);
}
function tunnelKey(peer: string, id: string): string { return `${peer}\u0000${id}`; }
function opposite(direction: Direction): Direction { return direction === "c2s" ? "s2c" : "c2s"; }
function concat(chunks: Uint8Array[]): Uint8Array {
  if (chunks.length === 1) return chunks[0]!;
  const output = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.byteLength, 0));
  let offset = 0;
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.byteLength; }
  return output;
}
function asError(error: unknown): Error { return error instanceof Error ? error : new Error(String(error)); }

async function connectWithTimeout(
  hostname: string,
  port: number,
  timeoutMs: number,
  socket: Bun.SocketHandler<undefined>,
): Promise<Bun.Socket<undefined>> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      Bun.connect({ hostname, port, socket, allowHalfOpen: true }),
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(`connect timed out after ${timeoutMs}ms`)), timeoutMs); }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
