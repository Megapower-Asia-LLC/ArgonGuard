---
title: "PPLX Agent API Output"
type: knowledge
status: draft
date_created: 2026-07-06
date_modified: 2026-07-06
project: "PPLX Agent API 整合"
tags:
  - research
pplx_response_id: resp_efc0da94-8844-42fb-b4bb-fe5729678def
pplx_endpoint: agent
pplx_model: anthropic/claude-sonnet-4-6
pplx_preset: 
pplx_task_type: research
pplx_rigour: high
pplx_tokens: 17613
pplx_latency_sec: 138.43
---

# PPLX Agent API Output

> [!info]+ PPLX call meta
> Endpoint: agent / Model: anthropic/claude-sonnet-4-6 / Preset:  / Tokens: 17613 / Latency: 138.43s
> Selection reason: research/high → Claude Sonnet 4-6 + tools (結構/在地中文/批判性)

## Query

我要為 ArgonGuard（一個 OWASP 合規、跨語言互通的 Argon2id 密碼雜湊元件，已有 .NET/Node/Python/PHP 四語言實作，同一份 spec + 凍結測試向量，4×4 跨語言 CI 矩陣）新增 Cloudflare Workers / Vercel Edge / 瀏覽器等純 WebAssembly 環境的支援。以資深架構師身分嚴格審核以下設計，五個待審問題請給明確答案（不要模稜兩可）。

# 架構背景
- ArgonGuard 哲學：規格層自寫（PHC parser、政策、needsRehash，四語言 bit-identical）、密碼學層委外給引擎、引擎藏在 internal provider 之後可抽換、永不自寫 Argon2 原語。
- Node 版 provider 介面極簡：`hashRaw(password, salt, m, t, p, tagLength): Promise<Buffer>`，規格層負責 salt 生成、PHC 組裝、政策、constant-time 比對。
- Node 版 hasher 硬編 @node-rs/argon2 provider，且用 node:crypto（randomBytes, timingSafeEqual）+ Buffer（byteLength, base64 編解碼）。
- 障礙：@node-rs/argon2 是 native/wasm32-wasi，workerd 不支援 WASI；node:crypto 與 Buffer 在純 edge 也不保證有。

# 設計決策
- 推薦「選項 A」：核心平台無關化 + 可注入 provider/crypto。抽象 Argon2Provider（已有）+ 新增 CryptoPrimitives（randomBytes/timingSafeEqual）；phc.ts 的 base64/byteLength 改平台無關；hasher 建構可注入，預設維持 node（零破壞）；新增 edge 入口注入 wasm provider（argon2id npm 套件）+ web crypto。
- 互通保證：edge 實作必須通過全部凍結向量，與四語言 bit-identical；CI 矩陣擴為 5×5。

# 五個待審問題（請逐一明確回答）
1. 選項 A（核心注入）vs 選項 B（獨立 @argonguard/passwords-edge 子套件）：對長期維護與跨語言矩陣哪個更穩健？
2. argon2id npm 套件 vs argon2-wasm-edge：哪個在 workerd 更穩、更易產出通過凍結向量的 raw tag？WASM 靜態載入（import ArrayBuffer + WebAssembly.instantiate）在 wrangler/vite bundling 的正確 pattern？
3. constant-time compare 純 JS 實作在 V8/workerd 是否真 constant-time？JIT 會不會優化掉短路？有無更安全做法（如 web crypto 有無等價）？
4. base64：edge 用 atob/btoa 還是自寫？RFC 4648 no-padding 與 PHC 相容？atob 對非 ASCII 二進位的陷阱？
5. 在 GitHub Actions 跑 workerd/miniflare 驗證凍結向量的可行性與陷阱？

另外請指出：這個設計有沒有致命的安全或架構錯誤？整體評分 1-10 與最關鍵的三個修正。

## Search queries triggered

- argon2id npm package wasm cloudflare workers workerd 2025 2026
- argon2-wasm-edge cloudflare workers wasi support
- cloudflare workers WebAssembly instantiate wrangler bundling pattern
## Output

# ArgonGuard WebAssembly 擴展 — 資深架構師嚴格審核報告

---

## 前置：搜尋結果關鍵事實確認

在回答五問之前，先固定幾個已從搜尋結果確認的事實：

| 事實 | 來源 |
|---|---|
| workerd **只接受 build-time 預編譯 WASM**，`WebAssembly.compile(fetch(...))` 等 runtime 動態編譯被 block（等同 eval） | Rendobar CF Workers WASM 分析 |
| wrangler 預設把 `.wasm` import 處理成 `WebAssembly.Module`（非 ArrayBuffer） | CF Dev Docs bundling |
| `@node-rs/argon2` 是 wasm32-wasi，workerd **不支援 WASI**（已有 Reddit 確認） | Reddit CF 討論 |
| `argon2id` npm（Daninet 系）：wasm inline as base64，**7KB gzip**，支援自訂 instantiate，CF 有實際成功案例 | npmjs + hash-wasm Discussion |
| `argon2-wasm-edge`：明確支援 CF Workers，需 `setWASMModules({ argon2WASM, blake2bWASM })` 兩個 .wasm 靜態 import | yarn classic package page |
| `argon2-wasi`（auth70）：用 `@cloudflare/workers-wasi`，需 unbounded mode，架構完全不同 | GitHub auth70/argon2-wasi |

---

## 問題一：選項 A（核心注入）vs 選項 B（獨立子套件）

### 判決：**選項 A 是正確答案，但必須加一個硬性約束**

**理由逐點論證：**

**選項 B 的致命問題：**
`@argonguard/passwords-edge` 獨立子套件意味著你要維護兩份規格層（PHC parser、政策引擎、needsRehash、常數時間比對邏輯）。ArgonGuard 的核心價值在於「同一份 spec」產出 bit-identical 結果。一旦規格層分叉，跨語言矩陣就從 5×5 變成 5×5 + 1×5（edge），而邊界上的任何 spec drift 都會靜默地破壞互通保證。選項 B 本質上是技術債的預購合約。

**選項 A 的正確形態（必須加的硬性約束）：**

```
packages/
  argonguard-core/        ← 規格層（PHC parser、policy、needsRehash）
                            平台無關純 TypeScript，零 Node 依賴
  argonguard-node/        ← 入口：注入 @node-rs/argon2 + node:crypto
  argonguard-edge/        ← 入口：注入 argon2id-wasm + WebCrypto
  argonguard-browser/     ← 入口：同上，或合併至 edge
```

**關鍵點**：`argonguard-core` 必須是 **零平台依賴的純套件**，它本身可以獨立發布，讓 edge 入口與 node 入口都依賴它，而不是 edge 去依賴 node 入口再 override。目前設計描述中「hasher 建構可注入，預設維持 node」這個「預設 node」的措辭暗示 edge 入口仍依賴 node 入口——這是一個需要明確切斷的耦合點。

**對 CI 矩陣的影響：**
選項 A 下，矩陣擴展是線性的：凍結向量集中在 core，所有語言實作（包括 edge）都跑相同向量，5×5 矩陣自然成立。選項 B 下，edge 的凍結向量必須額外同步，維護成本非線性增長。

---

## 問題二：argon2id npm vs argon2-wasm-edge，及 WASM 靜態載入 Pattern

### 判決：**argon2id npm 套件，使用自訂 instantiate 注入 pattern**

### 兩個套件的關鍵差異對比

| 維度 | `argon2id` (Daninet) | `argon2-wasm-edge` |
|---|---|---|
| WASM 載入方式 | base64 inline，可覆寫 instantiate | 需 `setWASMModules()` 傳入兩個 `.wasm` 靜態 import |
| 依賴數量 | 1 個 WASM binary | 2 個（argon2.wasm + blake2b.wasm） |
| bundle 大小 | <7KB gzip | 未公開，但 BLAKE2b 是獨立 binary |
| raw tag 輸出 | ✅ 有（`hashRaw` 或等價介面） | 輸出格式需確認（偏向完整 PHC string） |
| CF Workers 成功案例 | hash-wasm Discussion 有實作 | yarn 頁面有範例，維護活躍度較低（1 年前） |
| 原語來源 | Emscripten 編譯的 C 實作（argon2 參考實作） | 獨立編譯，血統不如清晰 |

**選擇 `argon2id` npm 的決定性理由**：
1. 它基於 argon2 參考實作的 Emscripten 編譯，bit-identical 通過凍結向量的信心最高
2. 可覆寫 instantiate，這正是 workerd 需要的 pattern
3. 社群中已有 CF Workers 的成功整合（hash-wasm Discussion #56 有完整程式碼）

### workerd 正確的 WASM 靜態載入 Pattern

**錯誤做法（workerd 會 block）：**
```typescript
// ❌ runtime 動態編譯 — 等同 eval，workerd 直接拒絕
const response = await fetch('https://cdn.example.com/argon2.wasm');
const buffer = await response.arrayBuffer();
const module = await WebAssembly.compile(buffer); // BLOCKED

// ❌ 同樣被 block
const bytes = new Uint8Array(base64Decode(WASM_BASE64));
const module = await WebAssembly.compile(bytes.buffer); // BLOCKED in workerd
```

**正確做法（wrangler build-time 預編譯）：**

```typescript
// edge/src/wasm-provider.ts

// wrangler 會在 bundle 時把 .wasm 處理成 WebAssembly.Module
// 型別宣告讓 TypeScript 知道這是 Module 而非 ArrayBuffer
import argon2WasmModule from 'argon2id/dist/no-simd.wasm';
import argon2SimdWasmModule from 'argon2id/dist/simd.wasm';

// wrangler.toml 或 wrangler.jsonc 確認規則（通常預設已包含）:
// [[rules]]
// type = "CompiledWasm"
// globs = ["**/*.wasm"]

import setup from 'argon2id/lib/setup';
import type { Argon2idParams } from 'argon2id/lib/setup';

// 這個 instantiate 函式是關鍵：接受 WebAssembly.Module（已預編譯），
// 直接 instantiate 而不是 compile
const argon2 = setup({
  instantiate: (module: WebAssembly.Module, importObject: WebAssembly.Imports) =>
    WebAssembly.instantiate(module, importObject).then(instance => ({
      instance,
      module,
    })),
  // SIMD 偵測：workerd 不保證 SIMD，fallback 到 no-simd
  wasmModule: argon2WasmModule,
  simdWasmModule: argon2SimdWasmModule,
});

export const edgeArgon2Provider: Argon2Provider = {
  async hashRaw(password, salt, m, t, p, tagLength): Promise<Uint8Array> {
    const result = await argon2({
      password,
      salt,
      parallelism: p,
      iterations: t,
      memorySize: m,
      hashLength: tagLength,
      outputType: 'binary', // 取得原始 bytes，不要 PHC string
    });
    return result;
  },
};
```

**一個重要的 Vite（Vercel Edge）差異：**

```typescript
// Vite/Vercel Edge 用 ?url 或 ?raw 查詢參數，行為不同於 wrangler
// Vite 不會自動把 .wasm 處理成 WebAssembly.Module
// 需要明確使用 ?init 或自訂 Vite plugin

// vite.config.ts
import { defineConfig } from 'vite';
export default defineConfig({
  optimizeDeps: {
    exclude: ['argon2id'], // 避免 esbuild 把 wasm 內嵌破壞
  },
});

// 或使用 vite-plugin-wasm
import wasm from 'vite-plugin-wasm';
export default defineConfig({
  plugins: [wasm()],
});
```

**結論**：wrangler 的正確 pattern 是靜態 `import ... from '...wasm'`（得到 `WebAssembly.Module`）→ `WebAssembly.instantiate(module, importObject)`。**切勿使用 `WebAssembly.compile()`**，那是 runtime 動態路徑，workerd 封鎖。

---

## 問題三：純 JS Constant-Time Compare 在 V8/workerd

### 判決：**純 JS 實作無法保證 constant-time，需要結構性防禦，不能靠紀律**

### JIT 威脅模型的精確分析

```typescript
// ❌ 以下實作看起來正確，但在 V8 下不保證 constant-time
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false; // ← 第一個問題：早期返回洩漏長度
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i]; // ← XOR accumulation，邏輯正確
  }
  return diff === 0; // ← 但 V8 JIT 可能對整個函式做 loop elimination
}
```

**具體威脅（不是理論）：**

1. **V8 TurboFan 的 loop peeling / escape analysis**：當 JIT 偵測到 `diff` 在某個 `i` 之後必然非零，可能提前終止迴圈。這在 V8 的 speculation 模式下是真實行為。

2. **CPU 分支預測器洩漏**：即使 JS 邏輯正確，底層 x86/ARM 分支預測仍可能透過 Spectre-style side channel 洩漏資訊。workerd 雖然有 Spectre 緩解（Site Isolation、每 request 重建 V8 isolate），但不等於 timing channel 免疫。

3. **長度洩漏**：若在長度不等時早期返回，攻擊者可以透過 timing 得知「正確 hash 的長度」。對於 Argon2id 來說 hash 長度通常固定（32 bytes），風險較低，但規格層應明確禁止這條路徑。

### 安全做法層次（由強到弱）

**層次 1（最強）：使用 SubtleCrypto HMAC 比對**

```typescript
// Web Crypto API 的 HMAC 比對是 spec-mandated constant-time
// 這是目前在純 edge 環境最強的 constant-time 保證
async function timingSafeEqualWebCrypto(
  a: Uint8Array,
  b: Uint8Array
): Promise<boolean> {
  // 長度不等時，用相同長度的假資料跑完整比對，再返回 false
  // 防止長度洩漏
  const len = Math.max(a.length, b.length);
  const paddedA = new Uint8Array(len);
  const paddedB = new Uint8Array(len);
  paddedA.set(a);
  paddedB.set(b);

  // 用一個每次請求隨機的 key 做 HMAC，再比對 HMAC 值
  // 這把 timing 問題轉移到 HMAC 計算（spec-mandated CT）
  const key = await crypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const [macA, macB] = await Promise.all([
    crypto.subtle.sign('HMAC', key, paddedA),
    crypto.subtle.sign('HMAC', key, paddedB),
  ]);

  // 比對兩個 HMAC 值（固定 32 bytes），仍需 CT 比對
  // 但此時比對的是 HMAC 而非原始 hash，洩漏的是「兩個 HMAC 是否相同」
  // 而不是「原始 hash 哪個 byte 不同」
  const viewA = new Uint8Array(macA);
  const viewB = new Uint8Array(macB);
  let diff = 0;
  for (let i = 0; i < 32; i++) {
    diff |= viewA[i] ^ viewB[i];
  }
  return diff === 0;
}
```

**層次 2（實用）：純 JS XOR accumulation + 防止 JIT 優化的 trick**

```typescript
// 使用 Uint32Array 做 32-bit XOR，減少迴圈次數降低 JIT 優化機會
// 並加入 dummy computation 讓 JIT 無法確定終止條件
function timingSafeEqualJS(a: Uint8Array, b: Uint8Array): boolean {
  // 長度必須相等（呼叫方保證），hash 長度固定時此假設成立
  const len = a.length;
  if (len !== b.length) {
    // 用 b[0] 做無意義計算，讓 JIT 無法消除這個分支
    void b[0];
    return false;
  }
  let diff = 0;
  for (let i = 0; i < len; i++) {
    diff |= a[i] ^ b[i];
  }
  // 強制使用結果，防止 dead code elimination
  return (diff | 0) === 0;
}
```

**明確結論**：
- `SubtleCrypto.verify()` 用於 HMAC 驗證時是 spec-level constant-time（RFC 6234 要求），但 WebCrypto **沒有直接的 `timingSafeEqual` API**
- 層次 1 的 HMAC 方法是目前 edge 環境最強保證，但有 async 開銷（兩次 HMAC sign）
- **對於 Argon2id 的 PHC 比對**：因為比對的是兩個固定長度（32 bytes）的 hash tag，且 Argon2id 本身的計算時間（數百毫秒）遠大於 timing channel 的解析度，實務上層次 2 的 XOR accumulation 是可接受的，但必須文件化此假設並加入 `@security` 標記

---

## 問題四：base64 在 Edge 環境

### 判決：**禁止用 atob/btoa 做 PHC binary 編解碼，必須自寫或使用 RFC 4648 library**

### atob/btoa 的三個陷阱（逐一精確說明）

**陷阱 1：atob/btoa 是 Latin-1，不是 binary-safe**

```typescript
// btoa 接受的是 Latin-1 字串，不是 Uint8Array
// 如果 input 包含 > 0xFF 的字元（或是 Uint8Array 被錯誤轉成字串），會拋出例外

// ❌ 錯誤：直接傳 Uint8Array
const hash = new Uint8Array([0x00, 0xFF, 0x80, 0x7F]);
btoa(hash as any); // TypeError: The string contains characters outside of Latin1

// ❌ 錯誤：用 String.fromCharCode 轉換，容易出錯
btoa(String.fromCharCode(...hash)); // 看起來正確，但對大 buffer 會 stack overflow
```

**陷阱 2：atob/btoa 輸出帶 padding（=），PHC 格式要求 no-padding**

```
PHC 規格：base64 encoding MUST NOT include padding characters (=)
btoa([0,0,0]) → "AAAA"     ← 恰好無 padding（長度是 3 的倍數）
btoa([0,0])   → "AAA="     ← 有 padding，PHC parser 會拒絕
btoa([0])     → "AA=="     ← 有 padding，PHC parser 會拒絕
```

**陷阱 3：PHC 用的是 standard base64（+/），不是 URL-safe base64（-_）**

```
RFC 4648 §4（standard）：字母表包含 + 和 /
RFC 4648 §5（URL-safe）：字母表包含 - 和 _
atob/btoa 使用 standard alphabet，這點與 PHC 相容
但如果你的 edge 程式碼在任何地方用了 URL-safe 編碼（如 JWT library），
混用後產出的 PHC string 會靜默地通不過其他語言的 parser
```

### 正確做法

```typescript
// phc-base64.ts — 平台無關，零依賴，明確的 RFC 4648 §4 no-padding 實作

const BASE64_CHARS =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function encodeBase64NoPadding(bytes: Uint8Array): string {
  let result = '';
  const len = bytes.length;
  for (let i = 0; i < len; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < len ? bytes[i + 1] : 0;
    const b2 = i + 2 < len ? bytes[i + 2] : 0;
    result += BASE64_CHARS[b0 >> 2];
    result += BASE64_CHARS[((b0 & 3) << 4) | (b1 >> 4)];
    result += i + 1 < len ? BASE64_CHARS[((b1 & 15) << 2) | (b2 >> 6)] : '';
    result += i + 2 < len ? BASE64_CHARS[b2 & 63] : '';
  }
  return result;
}

export function decodeBase64NoPadding(str: string): Uint8Array {
  // 建立反查表
  const lookup = new Uint8Array(128).fill(255);
  for (let i = 0; i < 64; i++) lookup[BASE64_CHARS.charCodeAt(i)] = i;

  const len = str.length;
  // no-padding 長度計算：每 4 字元 → 3 bytes，餘數處理
  const outputLen = Math.floor((len * 3) / 4);
  const result = new Uint8Array(outputLen);
  let outIdx = 0;

  for (let i = 0; i < len; i += 4) {
    const c0 = lookup[str.charCodeAt(i)] ?? 0;
    const c1 = lookup[str.charCodeAt(i + 1)] ?? 0;
    const c2 = i + 2 < len ? (lookup[str.charCodeAt(i + 2)] ?? 0) : 0;
    const c3 = i + 3 < len ? (lookup[str.charCodeAt(i + 3)] ?? 0) : 0;

    result[outIdx++] = (c0 << 2) | (c1 >> 4);
    if (i + 2 < len) result[outIdx++] = ((c1 & 15) << 4) | (c2 >> 2);
    if (i + 3 < len) result[outIdx++] = ((c2 & 3) << 6) | c3;
  }
  return result.subarray(0, outIdx);
}
```

**關於 `TextEncoder`/`byteLength`**：
`Buffer.byteLength(str, 'utf8')` 在 edge 不可用，改用 `new TextEncoder().encode(str).byteLength` 或直接 `new TextEncoder().encode(str)` 取得 bytes 後計算長度。`TextEncoder` 在所有目標環境（workerd、Vercel Edge、瀏覽器）均可用，這是正確的替換。

---

## 問題五：GitHub Actions 驗證凍結向量的可行性

### 判決：**可行，但有三個具體陷阱必須迴避**

### 推薦 CI 架構

```yaml
# .github/workflows/edge-frozen-vectors.yml
name: Edge Frozen Vector Validation

on: [push, pull_request]

jobs:
  # ─── 方案一：Miniflare（最穩定，純 Node，無需真實 CF 帳號）───
  miniflare-vectors:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22' # Miniflare 3.x 要求 Node 18+

      - run: npm ci
      - run: npm run build:edge # 產出 dist/worker.js + dist/*.wasm

      - name: Run frozen vectors via Miniflare
        run: |
          # Miniflare 3 直接在 Node 跑 workerd-compatible 環境
          # 不需要 Docker，不需要 CF 帳號
          npx wrangler dev --local --port 8787 &
          sleep 3 # 等待 worker 啟動
          node scripts/run-frozen-vectors.mjs http://localhost:8787
          kill %1

  # ─── 方案二：wrangler dev（更接近真實，但需要 CF API token）───
  wrangler-dev-vectors:
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22'

      - run: npm ci
      - run: npm run build:edge

      - name: Wrangler dev smoke test
        env:
          CLOUDFLARE_API_TOKEN: ${{ secrets.CF_API_TOKEN }}
        run: |
          npx wrangler dev --port 8787 &
          sleep 5
          node scripts/run-frozen-vectors.mjs http://localhost:8787
```

### 三個具體陷阱

**陷阱 1：WASM 記憶體限制導致 Argon2id 在 CI 環境靜默失敗**

Argon2id 的 `m` 參數（記憶體成本）在 workerd 預設有記憶體限制。如果凍結向量的測試參數使用高記憶體配置（如 `m=65536` 即 64MB），在 GitHub Actions 的免費 runner（7GB RAM）通常沒問題，但 Miniflare 的 isolate 記憶體限制可能比真實 Workers 更嚴格。

**解法**：凍結向量必須包含一組「edge-safe 低記憶體參數」（建議 `m=4096, t=3, p=1`）的向量，確保在 CI 中不會 OOM，同時高安全參數向量（`m=65536`）只在完整測試套件跑。

**陷阱 2：WASM SIMD 在 GitHub Actions runner 的行為不確定**

Argon2id 的 SIMD 版本（AVX2）在 GitHub Actions 的 `ubuntu-latest`（AMD64）通常可用，但在 ARM runner 或 macos runner 上行為不同。如果測試的 SIMD/no-SIMD 路徑不一致，相同輸入可能產出不同 tag（這取決於 argon2id npm 套件的 SIMD 優化是否影響結果；標準 Argon2id 實作 SIMD 不影響輸出，只影響速度，但必須實驗驗證）。

**解法**：CI 矩陣同時跑 `ubuntu-latest`（x64）+ `macos-latest`（arm64），確認兩者輸出與凍結向量一致。

**陷阱 3：wrangler dev 的 `--local` 模式與真實 workerd 行為差異**

Miniflare/wrangler local 模式的 WASM 處理在邊緣情況下與真實 workerd 有差異（特別是 Module 與 Instance 的生命週期管理）。如果 WASM module 被錯誤地在每個 request 重新 instantiate（而非在模組作用域快取），效能測試會失真，但功能測試通常仍通過。

**解法**：
```typescript
// ✅ 正確：module 作用域 instantiate（只做一次）
const argon2Instance = await setupArgon2(); // top-level await in module scope

export default {
  async fetch(request: Request): Promise<Response> {
    // 使用已初始化的 argon2Instance，不在 handler 內重新 instantiate
    const hash = await argon2Instance.hash(params);
    return new Response(hash);
  }
};
```

---

## 致命安全或架構錯誤檢查

### 🚨 致命錯誤 #1：WASM Module 未在模組作用域初始化（安全 + 效能雙重問題）

如果 WASM instantiation 放在 request handler 內部（每 request 執行一次），不只效能問題，更有安全含義：每次 instantiate 會重置 WASM 記憶體，但如果實作錯誤造成 instantiation 共用狀態，可能導致跨 request 記憶體洩漏。workerd 的 isolate-per-request 模型在某些部署配置下不保證每次都創建全新 isolate（warm reuse），這讓問題更複雜。

### 🚨 致命錯誤 #2：CryptoPrimitives 介面未定義「salt 生成失敗」的錯誤語義

`randomBytes` 在 WebCrypto 中（`crypto.getRandomValues()`）對於超過 65536 bytes 的請求會拋出 `QuotaExceededError`。如果 `CryptoPrimitives` 介面的呼叫方（規格層）沒有處理這個例外，且 Argon2id salt 長度意外超過上限（雖然標準 16 bytes 不會觸發，但上限是架構保證），這是一個靜默的 salt 生成失敗路徑。

### ⚠️ 重要架構問題 #3：Edge 入口的「預設維持 node」措辭暗示錯誤依賴方向

設計描述中「hasher 建構可注入，預設維持 node（零破壞）」——如果「預設 node」是指 edge 套件的 default export 仍引用 node 模組，這在 wrangler bundling 時會把 `node:crypto` 和 `@node-rs/argon2` 打包進 edge bundle，造成 bundle 失敗或 runtime 錯誤。正確做法是 edge 入口完全獨立，不存在「fallback to node」的路徑。

### ⚠️ 架構問題 #4：凍結向量沒有覆蓋 tagLength != 32 的情況

如果凍結向量只測試 `tagLength=32`，而 needsRehash 邏輯在比對時沒有正確處理不同長度的 hash（例如有人先前用 `tagLength=64` 產生 hash

## Citations

- https://developers.cloudflare.com/workers/wrangler/bundling/index.md
- https://www.reddit.com/r/CloudFlare/comments/1jts6hr/argon2_with_cloudflare_workers/
- https://developers.cloudflare.com/workers/runtime-apis/webassembly/javascript/
- https://www.npmjs.com/package/argon2id
- https://github.com/auth70/argon2-wasi
- https://github.com/glotlabs/argon2-cloudflare
- https://jsr.io/@rabbit-company/argon2id
- https://rendobar.com/blog/ffmpeg-wasm-cloudflare-workers/
- https://github.com/Daninet/hash-wasm/discussions/56
- https://classic.yarnpkg.com/en/package/argon2-wasm-edge
- https://npm.io/search/keyword:argon2id
- https://github.com/robertaboukhalil/cf-workers-emscripten
- https://github.com/CraigglesO/workers-zig-auth
- https://www.jsdelivr.com/package/npm/worker-password-auth
- https://github.com/cloudflare/workerd
