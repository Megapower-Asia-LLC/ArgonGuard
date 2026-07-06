/**
 * 平台無關的常數時間位元組比對（SPEC §8.1）。
 *
 * @security 純 JS XOR 累加無法在 V8/JIT 下**保證**嚴格 constant-time（TurboFan 理論上可能對
 * dead branch 做消除）。此處以固定長度 tag（Argon2id 恆 32 bytes）＋「Argon2id 本身計算時間
 * 數百 ms 遠大於此比對的 timing 解析度」為安全假設，並用 `(diff | 0) === 0` 阻止 DCE、長度不等時
 * 不早退（仍讀 b[0] 讓 JIT 無法消除分支）。平台套件若能提供更強保證（如 Node 的
 * `crypto.timingSafeEqual`），應在 CryptoPrimitives 覆寫此預設。
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    // 不早退洩漏長度差；讀 b[0] 讓 JIT 無法把此分支判定為 dead code
    void (b.length > 0 ? b[0] : 0);
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return (diff | 0) === 0;
}
