import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..", "..");
const [inputPath, outputPath] = process.argv.slice(2);

function emit(event) {
  process.stdout.write(JSON.stringify(event) + "\n");
}

if (!inputPath || !outputPath) {
  emit({ type: "error", error: "Usage: amx_runner.mjs <input.amx> <output.pwn>" });
  process.exit(2);
}

try {
  emit({ type: "progress", value: 8, message: "Reading the AMX file" });
  const input = await readFile(inputPath);
  emit({ type: "progress", value: 15, message: `Loaded ${input.length} bytes` });
  const moduleUrl = pathToFileURL(path.join(root, "lib", "deamx.js")).href;
  const { decompileAmx } = await import(moduleUrl);
  emit({ type: "progress", value: 25, message: "Running the DeAMX engine" });
  const result = await decompileAmx(input, path.basename(inputPath));
  if (!result || typeof result.source !== "string" || result.source.length === 0) {
    emit({ type: "error", error: "The DeAMX engine returned no source." });
    process.exit(1);
  }
  emit({ type: "progress", value: 90, message: "Writing the PWN output" });
  await writeFile(outputPath, result.source, "utf8");
  emit({
    type: "result",
    ok: true,
    name: result.name,
    failCount: result.failCount || 0,
    log: result.log || "",
    output_size: Buffer.byteLength(result.source, "utf8"),
  });
} catch (error) {
  emit({ type: "error", error: String(error && error.message ? error.message : error).slice(0, 2000) });
  process.exit(1);
}
