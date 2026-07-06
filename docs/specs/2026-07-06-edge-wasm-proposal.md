# ArgonGuard Edge/WASM 平台支援 — 設計方案

> 狀態：✅ Reviewed（PPLX research/high 審核共識，2026-07-06）· 定案見 §9
> 目標：讓 ArgonGuard 在 Cloudflare Workers / Vercel Edge / 瀏覽器等純 WebAssembly 環境可用，
> 與既有 .NET／Node／Python／PHP 實作 **bit-identical 互通**（同一份 spec、同一批凍結向量）。

## 1. 動機

ArgonGuard 的既定哲學（ADR 0004）：規格層自寫、密碼學層委外給引擎、引擎藏在 internal provider 之後可抽換。目前四語言引擎皆為原生模組。**Cloudflare Workers（workerd）不支援 native NAPI，也不支援 WASI**，因此 Node 版的 `@node-rs/argon2`（含其 `wasm32-wasi` fallback）無法在 workerd 執行。需要一個純 WebAssembly（無 WASI imports、靜態 import）的引擎路徑。

跨平台是 ArgonGuard 的核心價值主張；edge runtime 是現代自架後端（本案例：MegaNote on Cloudflare Workers）的主流，補上這塊讓「同一份密碼雜湊標準」真正覆蓋所有部署形態。

## 2. 技術現況（PPLX 已確認）

- `@node-rs/argon2` v2 的 WASM fallback 是 `wasm32-wasi` → workerd 不支援 WASI，實務上不可用。
- Workers 上最可靠的純 WASM Argon2id：**`argon2id` npm 套件**（hash-wasm 作者親自推薦，支援自訂 wasm loader / 靜態 import），或 `argon2-wasm-edge`。回傳 raw tag，PHC 由上層自組——**正好對應 ArgonGuard 的 provider 邊界**（provider 只需 `hashRaw`）。
- 成本：Argon2id `m=19456,t=2,p=1` 單次 hash ≈ 100ms CPU → **Cloudflare Workers 需 Paid Plan（$5/月）**，Free 的 10ms CPU 不足。

## 3. Edge 障礙清單（node built-in 依賴，共 4 處）

| 位置 | 依賴 | Edge 替代 |
|---|---|---|
| `engine/nodeRsArgon2Provider.ts` | `@node-rs/argon2`（native/WASI） | 新增 `wasmArgon2Provider`（`argon2id` 純 WASM） |
| `hasher.ts` `randomBytes` | node:crypto | `crypto.getRandomValues`（Web Crypto，Workers 原生） |
| `hasher.ts` `timingSafeEqual` | node:crypto | 自製 constant-time compare（純 JS，位元 XOR 累加） |
| `hasher.ts` / `phc.ts` `Buffer.*`（byteLength、base64 編解碼） | node:Buffer | `TextEncoder`（UTF-8 位元組長度）、Web 標準 base64 |

規格層 `phc.ts`（解析文法）、`policy.ts`、`profiles.ts`、`input.ts`、`errors.ts`、`reasonCodes.ts`、`legacy.ts` 的**邏輯**平台無關；只有 `phc.ts` 的 base64 helper 與 `hasher.ts` 的 crypto/Buffer 呼叫需抽象化。

## 4. 策略選項

**選項 A — 核心平台無關化 + 可注入 provider/crypto（推薦）**
- 抽象兩個 primitive 邊界：`Argon2Provider`（已存在）+ 新增 `CryptoPrimitives`（`randomBytes(n)` / `timingSafeEqual(a,b)`）
- base64 與 byteLength 改用平台無關實作（`phc.ts` 內），移除 Buffer 依賴
- `ArgonGuardPasswordHasher` 建構時可注入 provider + crypto，預設維持 node（零破壞既有 API）
- 新增 edge 入口（`@argonguard/passwords/edge` 或環境偵測工廠）注入 wasm provider + web crypto
- **同一個 hasher 類、同一份規格層、同一批凍結向量**——edge 只是換兩個注入點

**選項 B — 獨立 `@argonguard/passwords-edge` 子套件**
- 規格層抽成共用 core 套件，node/edge 各自組裝
- 隔離乾淨但有重複維護與版本同步成本；跨語言矩陣要多接一個目標

**選項 C — 環境自動偵測，單一入口**
- import 時偵測 `globalThis.WebAssembly` + 缺 native → 自動選 wasm provider
- 對使用者最透明，但「魔法」偵測在 bundler/SSR 邊界易踩雷（PPLX 提到 Workers 靜態 import 限制）

## 5. 推薦：選項 A

理由：最小化重複、保住單一 spec/單一凍結向量/單一 hasher 的架構純度；provider 邊界本就是為此設計（ADR 0004「引擎可抽換」）；edge 與 node 產出因同 Argon2id 參數 + PHC 格式而**天然 bit-identical**，凍結向量直接複用即為跨平台互通的證明。

## 6. 互通保證（不可退讓）

- edge 實作**必須**通過 `spec/vectors/v1` 全部凍結向量（deterministic / verify / reject / needs-rehash / input-limits / dummy-hashes），與四語言 bit-identical。
- CI 矩陣（守門 3）新增 edge 目標：在 workerd（`wrangler`/miniflare）或純 web 環境跑 harness，納入 5×5（原 4×4 + edge）round-trip。
- edge harness 遵循 `spec/harness-contract`。

## 7. 成本與範圍

- 消費端（如 MegaNote）在 Workers 用 edge 版做 Argon2id → 需 Paid Plan（$5/月）。此為 Argon2id 安全參數的固有成本，非 ArgonGuard 引入。
- 範圍外：不改任何既有語言實作的公開 API；不改 spec 參數/檔位（凍結）；不新增 profile。

## 8. 待審問題（給 PPLX）

1. 選項 A vs B：核心注入 vs 獨立子套件，對長期維護與跨語言矩陣哪個更穩健？
2. `argon2id` npm 套件 vs `argon2-wasm-edge`：哪個在 workerd 更穩、更易產出通過凍結向量的 raw tag？WASM 載入方式（靜態 import ArrayBuffer + `WebAssembly.instantiate`）在 wrangler bundling 的正確 pattern？
3. constant-time compare 純 JS 實作在 V8/workerd 是否真的 constant-time（JIT 會不會優化掉）？有無更安全做法？
4. base64：edge 用 `atob/btoa`（二進位安全性問題）還是自寫 base64？RFC 4648 no-padding 與 PHC 相容性？
5. CI：在 GitHub Actions 跑 workerd/miniflare 驗證凍結向量的可行性與陷阱？

---

## 9. PPLX 審核定案（v2）

PPLX research/high 審核，五問題全部有明確判決，並揪出 4 個架構問題。完整報告見 `docs/reviews/pplx-edge-wasm-review.md`。

### 9.1 策略：選項 A + 硬性約束——monorepo 三套件

選項 B（獨立 edge 子套件）判定為「技術債預購合約」（規格層分叉會靜默破壞互通）。選項 A 正確，但**必須**改為零耦合的三套件，`core` 可獨立發布，edge/node 都依賴 core，**不存在 edge → node 的 fallback 路徑**（致命錯誤 #3：否則 wrangler bundling 會把 `node:crypto`/`@node-rs/argon2` 打包進 edge bundle）：

```
packages/
  argonguard-core/   規格層純 TypeScript，零平台依賴（PHC parser、policy、
                     needsRehash、input、errors、profiles、base64、constant-time）
                     + Argon2Provider / CryptoPrimitives 介面
  argonguard-node/   注入 @node-rs/argon2 + node:crypto（既有實作遷入，公開 API 零變更）
  argonguard-edge/   注入 argon2id(WASM) + Web Crypto
```

原 node 版「hasher 建構可注入、預設維持 node」措辭作廢——改為 core 定義介面、各平台入口注入，無預設平台。凍結向量集中在 core，5×5 矩陣線性成立。

### 9.2 引擎：`argon2id` npm 套件（Daninet）

Emscripten 編譯自 argon2 參考實作、bit-identical 通過凍結向量信心最高、可覆寫 instantiate（workerd 所需）、hash-wasm Discussion #56 有 CF Workers 成功案例。**WASM 載入**：靜態 `import mod from 'argon2id/dist/*.wasm'`（得 `WebAssembly.Module`）→ `WebAssembly.instantiate(module, imports)`；**切勿 `WebAssembly.compile()`**（workerd 封鎖 runtime 動態編譯）。`wrangler.toml` 加 `[[rules]] type="CompiledWasm"`。provider `hashRaw` 用 `outputType: 'binary'` 取 raw tag。

### 9.3 base64：自寫 RFC 4648 §4 no-padding

禁用 `atob/btoa`（Latin-1 非 binary-safe、對 >0xFF 拋錯、`String.fromCharCode(...)` 大 buffer stack overflow、輸出帶 padding）。core 內自寫 standard alphabet（`+/`）no-padding 編解碼（PPLX 附完整實作）。`byteLength` 改 `new TextEncoder().encode(str).byteLength`。

### 9.4 constant-time 比對

純 JS XOR accumulation 無法保證 constant-time（V8 TurboFan loop elimination）。但 Argon2id tag 固定 32B、Argon2 計算時間（數百 ms）遠大於 timing channel 解析度，層次 2（`Uint32Array` XOR 累加 + 防 DCE `(diff|0)===0`）實務可接受，**必須文件化此假設 + `@security` 標記**。長度不等時不得早退（用 dummy computation 防 JIT 消除）。層次 1（每 request 隨機 key 的 HMAC 比對）為最強備選，有 async 開銷。

### 9.5 CI：Miniflare 跑凍結向量（5×5 矩陣）

Miniflare 3（Node 22，無需 CF 帳號）跑全部凍結向量。三陷阱緩解：(a) 加一組 edge-safe 低記憶體向量（`m=4096,t=3,p=1`）避免 CI OOM，高記憶體向量另跑；(b) 矩陣同跑 `ubuntu-latest`(x64) + `macos-latest`(arm64) 確認 SIMD/no-SIMD 輸出一致；(c) WASM 模組作用域 instantiate（top-level，非 per-request）。

### 9.6 四個必修錯誤

1. **致命 #1**：WASM module 模組作用域 instantiate（非 handler 內），避免效能失真與潛在跨 request 狀態
2. **致命 #2**：`CryptoPrimitives.randomBytes` 定義失敗語義——`crypto.getRandomValues` 對 >65536 bytes 拋 `QuotaExceededError`（標準 16B salt 不觸發，但介面契約要明確）
3. **致命 #3**：edge 入口零 node 依賴（見 §9.1）
4. **重要 #4**：凍結向量須覆蓋 `tagLength ≠ 32`，確保 needsRehash 對不同長度 hash 的比對正確

### 9.7 成本

消費端在 Workers 用 edge 版做 Argon2id（`m=19456`）單次 ≈ 100ms CPU → **需 Workers Paid Plan（$5/月）**，Free 的 10ms 不足。此為 Argon2id 安全參數固有成本。

**共識達成，可進入實作。** 實作順序：core 抽取（規格層 + 兩介面 + base64 + constant-time）→ node 遷入（凍結向量回歸）→ edge 套件（argon2id provider + Web Crypto）→ edge 凍結向量 conformance → 5×5 CI → 對抗式審查。
