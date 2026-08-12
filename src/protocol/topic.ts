import type { ArchiveMode, Direction, ProtectionMode, TopicParts } from "../types.ts";

const RESERVED_FIRST_LEVELS = new Set([
  "$sys",
  "$share",
  "$queue",
  "$bridge",
  "$local",
  "$delayed",
  "$forward",
  "$exclusive",
  "$control",
]);
const LEVEL_PATTERN = /^[A-Za-z0-9$][A-Za-z0-9._$-]*$/;
const NODE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export function validateTopicPrefix(prefix: string): string {
  if (!prefix) throw new Error("mqtt.topicPrefix must be a non-empty string");
  if (prefix.startsWith("/") || prefix.endsWith("/")) throw new Error("mqtt.topicPrefix cannot start or end with '/'");
  if (prefix.includes("//")) throw new Error("mqtt.topicPrefix cannot contain empty topic levels");
  if (prefix.includes("+") || prefix.includes("#")) throw new Error("mqtt.topicPrefix cannot contain MQTT wildcards");
  if (Buffer.byteLength(prefix, "utf8") > 128) throw new Error("mqtt.topicPrefix exceeds 128 UTF-8 bytes");
  const levels = prefix.split("/");
  if (levels.length > 8) throw new Error("mqtt.topicPrefix cannot contain more than 8 levels");
  for (const level of levels) {
    if (level === "." || level === "..") throw new Error("mqtt.topicPrefix cannot contain '.' or '..' levels");
    if (level.length > 32) throw new Error(`mqtt.topicPrefix level '${level}' exceeds 32 characters`);
    if (!LEVEL_PATTERN.test(level)) throw new Error(`mqtt.topicPrefix level '${level}' contains unsupported characters`);
  }
  if (RESERVED_FIRST_LEVELS.has(levels[0]!.toLowerCase())) {
    throw new Error(`mqtt.topicPrefix uses reserved topic space '${levels[0]}'`);
  }
  return prefix;
}

export function validateNodeId(nodeId: string, path = "nodeId"): string {
  if (!NODE_PATTERN.test(nodeId)) throw new Error(`${path} must match ${NODE_PATTERN}`);
  return nodeId;
}

export function buildBatchTopic(parts: TopicParts): string {
  validateTopicPrefix(parts.topicPrefix);
  validateNodeId(parts.toNodeId, "toNodeId");
  validateNodeId(parts.fromNodeId, "fromNodeId");
  return [
    parts.topicPrefix,
    parts.direction,
    parts.toNodeId,
    parts.fromNodeId,
    parts.archive,
    parts.protection,
    "batch",
  ].join("/");
}

export function buildNodeSubscription(topicPrefix: string, nodeId: string): string {
  validateTopicPrefix(topicPrefix);
  validateNodeId(nodeId);
  return `${topicPrefix}/+/${nodeId}/+/+/+/batch`;
}

export function parseBatchTopic(topic: string, topicPrefix: string): TopicParts {
  validateTopicPrefix(topicPrefix);
  const prefix = `${topicPrefix}/`;
  if (!topic.startsWith(prefix)) throw new Error("topic does not match configured topicPrefix");
  const rest = topic.slice(prefix.length).split("/");
  if (rest.length !== 6 || rest[5] !== "batch") throw new Error("invalid batch topic shape");
  const [direction, toNodeId, fromNodeId, archive, protection] = rest;
  if (direction !== "c2s" && direction !== "s2c") throw new Error("invalid direction");
  if (archive !== "tar" && archive !== "tgz") throw new Error("invalid archive mode");
  if (protection !== "plain" && protection !== "aead" && protection !== "rc4") {
    throw new Error("invalid protection mode");
  }
  return {
    topicPrefix,
    direction: direction as Direction,
    toNodeId: validateNodeId(toNodeId!, "toNodeId"),
    fromNodeId: validateNodeId(fromNodeId!, "fromNodeId"),
    archive: archive as ArchiveMode,
    protection: protection as ProtectionMode,
  };
}
