import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** 凍結向量／權威 artifact 載入工具（tests 專用）。 */

const SPEC_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "spec");

export function specFile(name: string): string {
  return join(SPEC_DIR, name);
}

export function loadSpecJson<T = any>(name: string): T {
  return JSON.parse(readFileSync(specFile(name), "utf8")) as T;
}

export function vectorEntries(file: string): any[] {
  return loadSpecJson<{ entries: any[] }>(join("vectors", "v1", file)).entries;
}

export function vectorEntry(file: string, id: string): any {
  const entry = vectorEntries(file).find((e) => e.id === id);
  if (entry === undefined) throw new Error(`${file}: ${id} not found`);
  return entry;
}

export function hex(s: string): Buffer {
  return Buffer.from(s, "hex");
}

export function utf8(bytes: Buffer): string {
  return bytes.toString("utf8");
}
