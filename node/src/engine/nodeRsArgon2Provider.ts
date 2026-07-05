import { Algorithm, hashRaw, Version } from "@node-rs/argon2";
import { UnsupportedEnvironmentError } from "../errors.js";
import { ReasonCodes } from "../reasonCodes.js";
import type { Argon2Provider } from "./provider.js";

/**
 * @node-rs/argon2（RustCrypto，預編譯原生模組）引擎。
 * memoryCost 單位 KiB（spec/engine-units.json: node_node_rs_argon2_memoryCost）。
 * async hashRaw 走 napi 背景執行緒，不佔用 event loop。
 */
export class NodeRsArgon2Provider implements Argon2Provider {
  constructor() {
    // fail-fast（SPEC §7 UnsupportedEnvironment）：原生 binding 缺失時給 typed error
    if (typeof hashRaw !== "function") {
      throw new UnsupportedEnvironmentError(ReasonCodes.Argon2idUnavailable);
    }
  }

  hashRaw(password: Uint8Array, salt: Uint8Array, m: number, t: number, p: number, tagLength: number): Promise<Buffer> {
    return hashRaw(asBuffer(password), {
      salt: asBuffer(salt),
      memoryCost: m,
      timeCost: t,
      parallelism: p,
      outputLen: tagLength,
      algorithm: Algorithm.Argon2id,
      version: Version.V0x13,
    });
  }
}

function asBuffer(bytes: Uint8Array): Buffer {
  return Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}
