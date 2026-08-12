import { loadConfig } from "./config/load.ts";
import { LocalListeners } from "./net/listeners.ts";
import { MqttBatchNode } from "./mqtt/client.ts";
import { RecordBatcher } from "./tunnel/batcher.ts";
import { TunnelManager } from "./tunnel/manager.ts";

async function main(): Promise<void> {
  const configPath = parseConfigPath(process.argv.slice(2));
  const config = await loadConfig(configPath);
  if (config.batch.protection === "rc4") console.warn("WARNING: batch.protection='rc4' is compatibility-only and provides no authenticated integrity. Use 'aead'.");

  const mqtt = new MqttBatchNode(config);
  const batcher = new RecordBatcher(config, mqtt, mqtt.protectionKey);
  const manager = new TunnelManager(config, batcher);
  const listeners = new LocalListeners(config, manager);
  mqtt.onBatch = (batch, context) => manager.handleBatch(batch, context);
  mqtt.onError = (error) => console.error(`[mqtt] ${error.message}`);

  await mqtt.start();
  listeners.start();
  console.log(`tcp_over_mqtt ${config.role} node '${config.nodeId}' is running; subscribed under '${config.mqtt.topicPrefix}'.`);
  for (const listener of config.listeners) console.log(`listener '${listener.name}' (${listener.type}) on ${listener.listenHost}:${listener.listenPort} -> ${listener.toNodeId}`);

  let stopping = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (stopping) return;
    stopping = true;
    console.log(`received ${signal}; stopping...`);
    listeners.close();
    manager.close();
    await batcher.close();
    await mqtt.close();
  };
  process.once("SIGINT", () => { void shutdown("SIGINT"); });
  process.once("SIGTERM", () => { void shutdown("SIGTERM"); });
}

function parseConfigPath(args: string[]): string {
  if (args.length === 2 && args[0] === "--config") return args[1]!;
  console.error("Usage: bun run src/cli.ts --config <path-to-jsonc>");
  process.exit(2);
}

await main();
