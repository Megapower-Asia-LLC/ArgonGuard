# ADR 0006：Edge/WASM 平台——規格層抽 core ＋ WASM 引擎 ＋ 三套件零耦合

**狀態**：Accepted（Edge/WASM 設計 PPLX research/high 審核共識，2026-07-06）

## 背景

跨平台是 ArgonGuard 的核心價值主張，但既有 JS 實作（`@argonguard/passwords`）依賴 `@node-rs/argon2`（native NAPI）與 `node:crypto`。**Cloudflare Workers（workerd）不支援 native NAPI，也不支援 WASI**，`@node-rs/argon2` 的 `wasm32-wasi` fallback 也不可用。現代自架後端（本案例：MegaNote on Cloudflare Workers）以 edge runtime 為主流，需要一條純 WebAssembly（無 WASI imports、靜態 import）的引擎路徑。

完整設計與五問題判決見 `docs/specs/2026-07-06-edge-wasm-proposal.md`；審核報告見 `docs/reviews/pplx-edge-wasm-review.md`。

## 決策

**JS/TS 生態改為零耦合三套件 monorepo**（PPLX 否決了「node 版建構可注入、預設維持 node」與「獨立 edge 子套件分叉規格層」兩案）：

```
@argonguard/core          規格層純 TypeScript，零平台依賴：PHC parser/encoder、
                          OWASP frontier 政策、needsRehash、input、base64（RFC 4648 no-pad）、
                          constant-time ＋ Argon2Provider / CryptoPrimitives 兩個注入介面。
                          不對終端暴露公開 hasher。
  ├─ @argonguard/passwords        注入 @node-rs/argon2 + node:crypto（既有實作遷入，公開 API 零變更）
  └─ @argonguard/passwords-edge   注入 argon2id(WASM) + Web Crypto
```

要點（皆為審核定案的硬性約束）：

- **引擎**：`argon2id` npm 套件（Daninet，Emscripten 編譯自 argon2 參考實作）——bit-identical 通過凍結向量信心最高、可覆寫 `instantiate`（workerd 所需）。WASM 靜態 `import` 得 `WebAssembly.Module` → `WebAssembly.instantiate(module, imports)`；**切勿 `WebAssembly.compile()`**（workerd 封鎖 runtime 動態編譯）。`wrangler.toml` 加 `[[rules]] type="CompiledWasm"`。
- **edge 入口零 node 依賴**：不存在 edge → node 的 fallback 路徑，否則 wrangler bundling 會把 `node:crypto`／`@node-rs/argon2` 打包進 edge bundle。
- **base64 自寫**：禁 `atob/btoa`（Latin-1 非 binary-safe、輸出帶 padding）；core 內自寫 RFC 4648 §4 standard alphabet no-padding。`byteLength` 用 `TextEncoder`。
- **constant-time**：純 JS `Uint32Array` XOR 累加＋防 DCE（`(diff|0)===0`），長度不等不早退。**明文記載**此在 V8/workerd 非嚴格 constant-time 的假設（Argon2 數百 ms 計算遠大於 timing channel 解析度，且 tag 固定 32B）；見 SPEC §8.1 註。
- **記憶體守衛**：argon2id 把 `m` KiB 放進 WASM 線性記憶體；`highest`（131072 KiB）需 2049 頁 > Workers 128 MiB isolate（2048 頁）。edge 預設上限 2048 頁，超上限拋 `UnsupportedEnvironmentError`（typed error，非不透明 OOM）；可傳 `maxWasmPages` 調高（瀏覽器/Vercel）。見 SPEC §8.8。

## 理由

- 選項 B（獨立 edge 子套件各自維護規格層）被判為「技術債預購合約」——規格層分叉會靜默破壞互通。抽 core 讓**單一 spec／單一凍結向量／單一規格層邏輯**成立，5×5 矩陣線性成立。
- provider 邊界本就是為「引擎可抽換」設計（ADR 0004）；edge 與 node 因同 Argon2id 參數＋PHC 格式而天然 bit-identical，凍結向量直接複用即為跨平台互通的證明。
- 範圍外（不退讓）：不改任何既有語言實作的公開 API、不改 spec 參數/檔位（凍結）、不新增 profile。

## 後果

- JS/TS 規格層邏輯只改 `core/`，node/edge 不得各自分叉。
- 守門 3 擴為 5×5；edge 在真 workerd（Miniflare 3，x64＋arm64）驗證，另加一組 edge-safe 低記憶體向量（`m=4096,t=3,p=1`）避免 CI OOM，並要求凍結向量覆蓋 `tagLength ≠ 32`（needsRehash 對不同長度 hash 的比對正確性）。
- 消費端在 Workers 用 Argon2id 需 Workers Paid Plan（$5/月），屬 Argon2id 安全參數固有成本、非 ArgonGuard 引入。
- Edge/WASM 已通過對抗式審查（記憶體守衛、負向量 workerd、型別邊界修復）。
