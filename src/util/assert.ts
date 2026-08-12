export function assertObject(value: unknown, path: string): asserts value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${path} must be an object`);
  }
}

export function assertNoUnknownKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  path: string,
): void {
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(value)) {
    if (!allowedSet.has(key)) throw new Error(`${path}.${key} is not a supported configuration field`);
  }
}

export function requiredString(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${path} must be a non-empty string`);
  return value;
}

export function optionalString(value: unknown, path: string): string | undefined {
  if (value === undefined) return undefined;
  return requiredString(value, path);
}

export function booleanValue(value: unknown, path: string, fallback?: boolean): boolean {
  if (value === undefined && fallback !== undefined) return fallback;
  if (typeof value !== "boolean") throw new Error(`${path} must be a boolean`);
  return value;
}

export function integerValue(
  value: unknown,
  path: string,
  options: { min: number; max: number; fallback?: number },
): number {
  if (value === undefined && options.fallback !== undefined) return options.fallback;
  if (!Number.isInteger(value) || (value as number) < options.min || (value as number) > options.max) {
    throw new Error(`${path} must be an integer between ${options.min} and ${options.max}`);
  }
  return value as number;
}

export function requiredArray(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new Error(`${path} is required and must be an array; use [] to explicitly allow all values`);
  }
  return value;
}

export function stringArray(value: unknown, path: string, required = false): string[] {
  if (value === undefined && !required) return [];
  const items = required ? requiredArray(value, path) : value;
  if (!Array.isArray(items)) throw new Error(`${path} must be an array`);
  return items.map((item, index) => requiredString(item, `${path}[${index}]`));
}

export function numberArray(value: unknown, path: string, required = false): number[] {
  if (value === undefined && !required) return [];
  const items = required ? requiredArray(value, path) : value;
  if (!Array.isArray(items)) throw new Error(`${path} must be an array`);
  return items.map((item, index) => integerValue(item, `${path}[${index}]`, { min: 1, max: 65535 }));
}
