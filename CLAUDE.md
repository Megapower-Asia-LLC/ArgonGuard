# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 專案概觀

ArgonGuard 是一套跨語言（.NET／Node.js／Python／PHP）互通的 **Argon2id** 密碼雜湊元件庫。核心約束：**完全符合 OWASP Password Storage Cheat Sheet、演算法固定 Argon2id（RFC 9106）**。四種語言實作彼此可驗證對方產生的雜湊。

**單一真相來源（SOT）**：`spec/SPEC.md`（normative，RFC 2119）。所有實作行為以它與 `spec/reference/dotnet-baseline.md`（.NET 參考實作定型）為準。設計理念與決策見 `docs/`。

## 架構（大局，需讀多檔才懂的部分）

**spec-first monorepo**：規格層與機器可讀權威 artifact 是第一等公民，四語言實作跟隨它們，而非各自為政。

- `spec/` 是所有實作的權威來源，**改這裡等於改契約**：
  - `SPEC.md` — normative 規格
  - `reason-codes.json` — 全部 reason code 的權威枚舉（四語言輸出字串必須 bit-identical）
  - `engine-units.json` — 各引擎 memory 參數單位對照＋期望常數（PHP sodium 用 bytes、其餘 KiB，`memlimit = m × 1024`）
  - `profiles.snapshot.json` — profile／frontier append-only 快照（守門斷言用）
  - `harness-contract.json` — dev harness I/O 凍結 fixture
  - `vectors/v1/*.json` + `MANIFEST.sha256` — 凍結測試向量（**append-only；改既有 entry 禁止，要修走 v2 重凍**），來源見 `PROVENANCE.md`
- **每個語言實作共同分層**（`{lang}/src`）：PHC 嚴格 parser/encoder → Policy（frontier 地板＋天花板，純函式）→ internal Engine provider（引擎藏在此，不進公開 API）→ Api（三操作）→ Errors（五 typed error）→ Legacy（建構時注入的不可變 verifier 清單）。**規格層自寫、密碼學層委外**。
- **三核心操作語意**（`hashPassword`／`verifyPassword`／`needsRehash`）：`verifyPassword` 回 `false` 只代表密碼不符，其餘一律 typed error（不得以 false 偽裝）；`needsRehash` 用自寫 parser 不呼叫底層、對毀損資料拋錯不折疊成 true。dispatch 順序見 SPEC §6.2 與 baseline §1（演算法 token 前置判斷：非 argon2id 不套 argon2 嚴格文法）。

**跨語言一致性怎麼保證**（三道守門，都在 `.github/workflows/`）：
1. `guard.yml`（守門 1）：`spec/tools/guard.py` 斷言 frontier 表／`default==(19456,2,1)` 哨兵／MANIFEST checksum／快照 append-only／reason-code 一致
2. per-language `{dotnet,node,python,php}.yml`：各語言對凍結向量 conformance（.NET 雙 TFM）
3. `matrix.yml`（守門 3，擋 merge）：`spec/tools/matrix.py` 跑 4×4 round-trip（16 lang-pair × 凍結密碼集 × 三檔位）＋四語言 harness 契約

## 常用指令

```bash
# 各語言測試（本地）
cd dotnet && dotnet test                                    # net8.0（net48 由 CI Windows runner）
cd node   && npm ci && npm run build && npm test            # build 後測（harness import dist）
cd python && .venv/bin/pytest                               # venv 已備；重建見下
cd php    && composer test

# 單一測試
cd dotnet && dotnet test --filter "FullyQualifiedName~ConformanceTests"
cd node   && npx vitest run tests/conformance.test.ts
cd python && .venv/bin/pytest tests/test_conformance.py -k needs_rehash
cd php    && vendor/bin/phpunit --filter testVerifyMatchesExpected

# 跨語言與規格守門（由 repo 根執行）
python3 spec/tools/guard.py                                 # 守門 1：spec 不變式
python3 spec/tools/matrix.py                                # 守門 3：4×4 矩陣（需先 build 各 harness）
python3 spec/tools/run_contract.py -- $(cat dotnet/HARNESS_CMD)   # harness 契約（換語言改路徑）

# 凍結向量重產（改 gen_vectors.py 後；三來源一致才寫出）
cd spec/tools && ../../python/.venv/bin/python3 gen_vectors.py ../vectors/v1

# 備援引擎 / sodium-only nightly conformance（本地手動）
dotnet test dotnet/backup-engine-tests/Isopoh.Conformance.Tests
cd php && ARGONGUARD_TEST_FORCE_PROVIDER=sodium composer test   # 需 tests/bootstrap 定義 ARGONGUARD_TESTING
```

環境：本機 dotnet 在 `~/.dotnet/dotnet`（非 PATH）；Python venv 在 `python/.venv`；四語言工具鏈（argon2 CLI、PHP+sodium、Composer、Node、argon2-cffi）皆已裝。

## 修改時必須知道的約束

- **凍結向量是 append-only**。新增 entry 可以（會更新 MANIFEST，PROVENANCE 記一筆），改既有 entry 不行（走 `vectors/v2/`）。
- **reason code 字串改動**必須同步 `spec/reason-codes.json` 與四語言常數，否則守門 1 紅燈。
- **profile／frontier 常數改動**必須同步 `engine-units.json`、`profiles.snapshot.json`、四語言 Policy，且守門會擋降級（低於 OWASP frontier）。
- **normative spec 變更**觸發回饋迴路：spec 版本升、master plan 升版重審、四語言 conformance 重跑（見 `docs/plans` 的 Global Constraints「三版本軸」）。
- **加公開 API 時**：.NET 開了 `TreatWarningsAsErrors` + `GenerateDocumentationFile`，公開成員缺 XML doc 會 build 失敗。
- **跨語言 API 形狀刻意差異**（非 drift）：Node 為 async（Promise），.NET/Python/PHP 同步；建構子 Node 用 options 物件、其餘位置引數。

## 工作流程慣例（本專案 Goal，見 memory）

技術決策與 Perplexity（`pplx` dispatcher，`-t research -r high --prefer-opus`）協作取得共識後由 Claude 自決執行；業務/產品決策問 Aiken。審核紀錄全存 `docs/reviews/`。發佈需 Aiken 帳號步驟，清單在 `docs/ops/naming.md`＋`operations.md`。
