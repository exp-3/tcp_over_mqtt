import { mkdir, rm } from "node:fs/promises";
import { relative, resolve } from "node:path";

const rootDir = resolve(import.meta.dir, "..");
const distDir = resolve(rootDir, "dist");

interface BuildProfile {
  filename: string;
  target?: Bun.Build.CompileTarget;
}

const buildProfiles = {
  native: { filename: "tcp_over_mqtt" },
  "linux-x64": { target: "bun-linux-x64", filename: "tcp_over_mqtt-linux-x64" },
  "linux-arm64": { target: "bun-linux-arm64", filename: "tcp_over_mqtt-linux-arm64" },
  "windows-x64": { target: "bun-windows-x64", filename: "tcp_over_mqtt-windows-x64.exe" },
} as const satisfies Record<string, BuildProfile>;

type BuildProfileName = keyof typeof buildProfiles;

const requestedProfile = process.argv[2] ?? "native";

if (requestedProfile === "clean") {
  await rm(distDir, { recursive: true, force: true });
  console.log("Removed dist/.");
  process.exit(0);
}

if (!(requestedProfile in buildProfiles)) {
  console.error(`Unknown build profile '${requestedProfile}'.`);
  console.error(`Available profiles: ${Object.keys(buildProfiles).join(", ")}, clean`);
  process.exit(2);
}

const profile: BuildProfile = buildProfiles[requestedProfile as BuildProfileName];
const outfile = resolve(distDir, profile.filename);
await mkdir(distDir, { recursive: true });

const compileOptions: Bun.CompileBuildOptions = {
  outfile,
  // Secrets must be supplied explicitly by the service environment.
  autoloadDotenv: false,
  autoloadBunfig: false,
  ...(profile.target ? { target: profile.target } : {}),
};

const result = await Bun.build({
  entrypoints: [resolve(rootDir, "src/cli.ts")],
  compile: compileOptions,
  minify: true,
});

if (!result.success) {
  for (const log of result.logs) console.error(log);
  process.exit(1);
}

console.log(`Built ${relative(rootDir, outfile)}${profile.target ? ` for ${profile.target}` : " for the current platform"}.`);
