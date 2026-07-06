import { Algorithm, hashRaw, Version } from "@node-rs/argon2";
import { ReasonCodes, UnsupportedEnvironmentError, type Argon2Provider } from "@argonguard/core";

/**
 * @node-rs/argon2（RustCrypto，預編譯原生模組）引擎，實作 core Argon2Provider。
 * memoryCost 單位 KiB（spec/engine-units.json）。async hashRaw 走 napi 背景執行緒。
 */
export class NodeRsArgon2Provider implements Argon2Provider {
  constructor() {
    // fail-fast（SPEC §7 UnsupportedEnvironment）：原生 binding 缺失時給 typed error
    if (typeof hashRaw !== "function") {
      throw new UnsupportedEnvironmentError(ReasonCodes.Argon2idUnavailable);
    }
  }

  async hashRaw(password: Uint8Array, salt: Uint8Array, m: number, t: number, p: number, tagLength: number): Promise<Uint8Array> {
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
