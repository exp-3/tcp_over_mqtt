import type { AppConfig, ListenerConfig } from "../types.ts";
import type { TunnelManager } from "../tunnel/manager.ts";

export class LocalListeners {
  private readonly listeners: Bun.TCPSocketListener[] = [];

  public constructor(private readonly config: AppConfig, private readonly manager: TunnelManager) {}

  start(): void {
    for (const listener of this.config.listeners) this.listeners.push(this.startOne(listener));
  }

  close(): void {
    for (const listener of this.listeners) listener.stop(true);
    this.listeners.length = 0;
  }

  private startOne(listener: ListenerConfig): Bun.TCPSocketListener {
    return Bun.listen({
      hostname: listener.listenHost,
      port: listener.listenPort,
      allowHalfOpen: true,
      socket: {
        open: (socket) => this.manager.attachLocalSocket(socket, listener),
        data: (socket, data) => this.manager.localData(socket, new Uint8Array(data)),
        end: (socket) => this.manager.localEnd(socket),
        error: (socket, error) => this.manager.localError(socket, error),
        close: (socket, error) => {
          if (error) this.manager.localError(socket, error);
          else this.manager.localEnd(socket);
        },
        drain: (socket) => this.manager.socketDrain(socket),
      },
    });
  }
}
