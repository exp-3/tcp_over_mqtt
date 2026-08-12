/**
 * Resolve a secret from an environment variable, falling back to the
 * configuration value only when the environment variable is absent.
 */
export function resolveSecretValue(envName: string | undefined, fallback: string | undefined): string | undefined {
  if (envName !== undefined) {
    const value = process.env[envName] ?? fallback;
    if (value === undefined) {
      throw new Error(`environment variable ${envName} is absent and no configuration fallback is set`);
    }
    return value;
  }
  return fallback;
}
