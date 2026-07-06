# ArgonGuard

OWASP-compliant, cross-language & cross-platform **Argon2id** password hashing components.

A family of interoperable password-hashing components across **.NET / Node.js / Python / PHP / Edge (WASM)**: one language-neutral spec, one set of frozen test vectors, and five implementations that can each verify hashes produced by any of the others. The core algorithm is fixed to **Argon2id** (RFC 9106); the parameter policy fully follows the **OWASP Password Storage Cheat Sheet**.

[![guard](https://github.com/Megapower-Asia-LLC/ArgonGuard/actions/workflows/guard.yml/badge.svg)](https://github.com/Megapower-Asia-LLC/ArgonGuard/actions/workflows/guard.yml)
[![cross-lang-matrix](https://github.com/Megapower-Asia-LLC/ArgonGuard/actions/workflows/matrix.yml/badge.svg)](https://github.com/Megapower-Asia-LLC/ArgonGuard/actions/workflows/matrix.yml)

> 🌐 **English** below · [繁體中文](#繁體中文-zh-hant) further down.

## Why ArgonGuard

- **Fully OWASP-compliant**: the generating side always emits ≥ the OWASP-equivalent minimum; the verifying side accepts the entire OWASP frontier. The public API exposes **no numeric parameters**, so you cannot accidentally produce a below-standard hash.
- **Cross-language & cross-platform interop**: standard `$argon2id$v=19$…` PHC format; a hash produced by .NET verifies under Node/Python/PHP/Edge and vice versa (a 4×4 matrix + edge 5×5 gate merges).
- **Painless upgrades**: `needsRehash` + rehash-on-login gradually converges your store to newer parameters without forcing password resets.
- **Legacy migration**: inject a legacy verifier (bcrypt, etc.) at construction; the core never produces non-Argon2id hashes.
- **Standing on mature engines**: each platform delegates to a battle-tested engine (Konscious / @node-rs/argon2 / argon2-cffi / PHP-native / argon2id-WASM); ArgonGuard only owns the spec layer (PHC parsing, policy, format) and never implements the primitives itself.

## Install & Quickstart

| Platform | Install | Package |
|---|---|---|
| .NET | `dotnet add package ArgonGuard.Passwords` | [`ArgonGuard.Passwords`](dotnet/) |
| Node.js | `npm install @argonguard/passwords` | [`@argonguard/passwords`](node/) |
| Python | `pip install argonguard-passwords` | [`argonguard-passwords`](python/) |
| PHP | `composer require argonguard/passwords` | [`argonguard/passwords`](php/) |
| **Edge/WASM** | `npm install @argonguard/passwords-edge` | [`@argonguard/passwords-edge`](edge/) — Cloudflare Workers / Vercel Edge / browser |

```csharp
// .NET
var hasher = new ArgonGuardPasswordHasher();          // default profile
string stored = hasher.HashPassword(password);
if (hasher.VerifyPassword(password, stored)) {
    if (hasher.NeedsRehash(stored)) Save(hasher.HashPassword(password));
}
```

```ts
// Node.js / Edge — verifyPassword is async, always await it (see per-package security notes)
const hasher = new ArgonGuardPasswordHasher();
const stored = await hasher.hashPassword(password);
if (await hasher.verifyPassword(password, stored)) {
  if (hasher.needsRehash(stored)) await save(await hasher.hashPassword(password));
}
```

See each package directory's README for full usage, migration examples, and security notes. **Edge note**: on Cloudflare Workers use the `high` profile at most — `highest` (128 MiB) exceeds the 128 MiB isolate limit and throws a typed error rather than an opaque OOM (see [`edge/README.md`](edge/README.md)).

## Core Design (summary)

- **Storage format**: standard PHC `$argon2id$v=19$m=<m>,t=<t>,p=1$<salt-b64>$<hash-b64>` (no padding).
- **Strength profiles** (the only public knob): `default` (19 MiB / 2 / 1, OWASP minimum), `high` (64 MiB), `highest` (128 MiB), all p=1.
- **Verification policy**: frozen OWASP frontier table (floor, anti-downgrade) + ceiling (anti-DoS); 16-byte CSPRNG salt, 32-byte tag, constant-time comparison.
- **Three core operations**: `hashPassword` / `verifyPassword` / `needsRehash`; `verifyPassword` returning `false` means only "wrong password" — everything else is a typed error (with a cross-language-identical reason code).

Full normative spec: [`spec/SPEC.md`](spec/SPEC.md); design rationale and decisions in [`docs/`](docs/).

## Repo Layout

```
spec/       language-neutral spec (SPEC.md), authoritative artifacts, frozen test vectors, guard/matrix tools
dotnet/ python/ php/         server-side implementations
core/ node/ edge/            Edge/WASM monorepo: core (platform-neutral spec layer) / node / edge (argon2id WASM)
docs/
├── specs/    consensus design docs (SOT)
├── plans/    implementation plans (master plan)
├── adr/      architecture decision records (ADR 0001-0005)
├── reviews/  external review records (Perplexity design + plan + adversarial reports)
└── ops/      naming / release / operations runbooks
.github/workflows/  per-language CI, guard 1 (spec invariants), guard 3 (4×4 matrix), edge (5×5 + workerd), nightly, release
```

## Development

```bash
cd dotnet && dotnet test                                              # .NET (net8.0; net48 via CI Windows runner)
cd node   && npm ci && npm run build && npm test                     # Node (delegates spec layer to @argonguard/core)
cd core   && npm ci && npm test                                       # Edge core (platform-neutral spec layer)
cd edge   && npm ci && npm test && npm run test:workerd               # Edge (argon2id WASM + real workerd via Miniflare)
cd python && python3 -m venv .venv && .venv/bin/pip install -e ".[dev]" && .venv/bin/pytest
cd php    && composer install && composer test                        # PHP

python3 spec/tools/guard.py     # guard 1: spec invariants
python3 spec/tools/matrix.py    # guard 3: 4×4 cross-language round-trip (build each harness first)
```

## License

MIT © Megapower Asia LLC

---

<a name="繁體中文-zh-hant"></a>

# ArgonGuard（繁體中文）

OWASP 合規、跨語言與跨平台的 **Argon2id** 密碼雜湊元件。

一套跨語言（.NET／Node.js／Python／PHP／**Edge (WASM)**）互通的密碼雜湊元件：同一份語言中立規格、同一批凍結測試向量，五種實作彼此可驗證對方產生的雜湊。核心演算法固定 **Argon2id**（RFC 9106），參數政策完全符合 **OWASP Password Storage Cheat Sheet**。

## 為什麼用 ArgonGuard

- **完全符合 OWASP**：產生端一律 ≥ OWASP 等效最低配置；驗證端接受整個 OWASP frontier。公開 API 沒有任何數字參數，你不可能不小心產出低於標準的雜湊。
- **跨語言與跨平台互通**：`$argon2id$v=19$…` 標準 PHC 格式；.NET 產的雜湊 Node／Python／PHP／Edge 都能驗，反之亦然（4×4 矩陣＋edge 5×5 擋 merge）。
- **升級無痛**：`needsRehash` + 登入後 rehash，逐步把儲存庫收斂到新參數，不必強迫使用者改密碼。
- **舊系統遷移**：建構時注入 legacy verifier（bcrypt 等），核心絕不產生非 Argon2id 雜湊。
- **站在成熟引擎上**：各平台委外給久經驗證的引擎（Konscious／@node-rs/argon2／argon2-cffi／PHP 原生／argon2id-WASM），ArgonGuard 只負責規格層（PHC 解析、政策、格式），從不自行實作密碼學原語。

## 安裝與快速上手

| 平台 | 安裝 | 套件 |
|---|---|---|
| .NET | `dotnet add package ArgonGuard.Passwords` | [`ArgonGuard.Passwords`](dotnet/) |
| Node.js | `npm install @argonguard/passwords` | [`@argonguard/passwords`](node/) |
| Python | `pip install argonguard-passwords` | [`argonguard-passwords`](python/) |
| PHP | `composer require argonguard/passwords` | [`argonguard/passwords`](php/) |
| **Edge/WASM** | `npm install @argonguard/passwords-edge` | [`@argonguard/passwords-edge`](edge/) — Cloudflare Workers／Vercel Edge／瀏覽器 |

```ts
// Node.js／Edge —— verifyPassword 是 async，務必 await（見各平台 README 安全注意事項）
const hasher = new ArgonGuardPasswordHasher();
const stored = await hasher.hashPassword(password);
if (await hasher.verifyPassword(password, stored)) {
  if (hasher.needsRehash(stored)) await save(await hasher.hashPassword(password));
}
```

各平台完整用法、遷移範例與安全注意事項見各目錄 README。**Edge 注意**：Cloudflare Workers 上最多用 `high` 檔位——`highest`（128 MiB）超過 128 MiB isolate 上限，會拋 typed error 而非不透明的 OOM（見 [`edge/README.md`](edge/README.md)）。

## 核心設計（摘要）

- **儲存格式**：標準 PHC `$argon2id$v=19$m=<m>,t=<t>,p=1$<salt-b64>$<hash-b64>`（no padding）。
- **強度檔位**（公開 API 唯一旋鈕）：`default`（19 MiB／2／1，OWASP 最低建議）、`high`（64 MiB）、`highest`（128 MiB），全部 p=1。
- **驗證政策**：OWASP frontier 凍結表（地板，防降級）＋天花板（防 DoS）；salt 每筆 16B CSPRNG、tag 32B、constant-time 比對。
- **三核心操作**：`hashPassword` / `verifyPassword` / `needsRehash`；`verifyPassword` 回 `false` 只代表密碼不符，其餘一律 typed error（帶跨語言一致 reason code）。

完整 normative 規格見 [`spec/SPEC.md`](spec/SPEC.md)；設計理念與決策見 [`docs/`](docs/)。

## Repo 佈局

```
spec/       語言中立規格（SPEC.md）、權威 artifact、凍結測試向量、守門/矩陣工具
dotnet/ python/ php/         server 端實作
core/ node/ edge/            Edge/WASM monorepo：core（平台無關規格層）／node／edge（argon2id WASM）
docs/       specs／plans／adr／reviews／ops
.github/workflows/  per-language CI、守門 1（spec 不變式）、守門 3（4×4 矩陣）、edge（5×5 + workerd）、nightly、release
```

## 開發

```bash
cd dotnet && dotnet test                                              # .NET（net8.0；net48 由 CI Windows runner）
cd node   && npm ci && npm run build && npm test                     # Node（規格層委由 @argonguard/core）
cd core   && npm ci && npm test                                       # Edge core（平台無關規格層）
cd edge   && npm ci && npm test && npm run test:workerd               # Edge（argon2id WASM + 真 workerd via Miniflare）
cd python && python3 -m venv .venv && .venv/bin/pip install -e ".[dev]" && .venv/bin/pytest
cd php    && composer install && composer test                        # PHP

python3 spec/tools/guard.py     # 守門 1：spec 不變式
python3 spec/tools/matrix.py    # 守門 3：4×4 跨語言 round-trip（需先 build 各語言 harness）
```

## License

MIT © Megapower Asia LLC
