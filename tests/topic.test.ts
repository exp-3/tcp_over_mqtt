import { describe, expect, test } from "bun:test";
import { buildBatchTopic, buildNodeSubscription, parseBatchTopic, validateTopicPrefix } from "../src/protocol/topic.ts";

describe("MQTT topics", () => {
  test("allows multi-level and custom dollar prefixes", () => {
    expect(validateTopicPrefix("$tenant/acme/prod")).toBe("$tenant/acme/prod");
  });

  test.each(["$SYS", "$share", "$QUEUE", "$bridge", "$local", "$delayed", "$forward", "$exclusive", "$CONTROL"])(
    "rejects reserved first level %s",
    (prefix) => expect(() => validateTopicPrefix(`${prefix}/x`)).toThrow(/reserved/),
  );

  test("builds, parses, and subscribes by destination node", () => {
    const parts = {
      topicPrefix: "tenant/acme/prod",
      direction: "c2s" as const,
      toNodeId: "server-a",
      fromNodeId: "connector-a",
      archive: "tgz" as const,
      protection: "aead" as const,
    };
    const topic = buildBatchTopic(parts);
    expect(topic).toBe("tenant/acme/prod/c2s/server-a/connector-a/tgz/aead/batch");
    expect(parseBatchTopic(topic, parts.topicPrefix)).toEqual(parts);
    expect(buildNodeSubscription(parts.topicPrefix, "server-a")).toBe("tenant/acme/prod/+/server-a/+/+/+/batch");
  });
});
