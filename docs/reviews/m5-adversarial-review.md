# M5 對抗式審查與驗證報告

**日期**：2026-07-06
**方法**：五視角對抗審查 workflow（16 agent：5 find-lens × 對抗式 verify，pipeline）＋端對端破壞性實測（四語言實際執行）。審查索引：Aiken OWASP 筆記 §5.3（Top 10 A02/A05/A07/A08/A09＋邊界案例清單）、SPEC.md、設計文件。
**結果**：11 findings → 對抗式複核後 10 CONFIRMED（全 low）、0 UNCERTAIN、1 REFUTED。**無 critical/high**。去重後 7 個獨特問題。

## Severity 分級與處置（M5 DoD）

| # | 問題 | severity | 處置 | 語言 |
|---|---|---|---|---|
| 1 | C5 長度預檢單位跨語言不一致（UTF-16 units vs code points vs bytes）——違反 bit-identical 賣點；極端情境同帳號跨節點登入結果相反 | low | **已修** | all/spec |
| 2 | PHP `ARGONGUARD_TEST_FORCE_PROVIDER` 在生產 code path（CWE-489；M4 引入） | low | **已修** | php |
| 3 | Node profile 閉集可被原型鏈鍵（`__proto__`/`constructor`…）繞過 | low | **已修** | node |
| 4 | PHP Native provider 用 `password_verify` 重解析原字串而非已驗政策的 parsed | low | **明文接受**（見下） | php |
| 5 | 1024-byte 檢查前對超長輸入 O(n) 掃描（.NET/Node/Python） | low | **文件**（M6 安全章節） | dotnet/node/python |
| 6 | PHP byte-passthrough：WTF-8 lone surrogate／overlong NUL 可過（SPEC I4 明文決定） | low | **文件**（混語言部署警告） | php |
| 7 | Node `verifyPassword` async，忘記 await → 靜默驗證繞過 | low | **文件**（醒目 await 警告＋建議 lint） | node |
| — | （REFUTED）1 項複核駁回，非真問題 | — | — | — |

## 已修（code）

**#1 C5 統一 UTF-8 bytes**：SPEC §4 C5 與 §6.2 步驟 2 明訂「512 UTF-8 bytes」。四語言：.NET `Encoding.UTF8.GetByteCount`（replacement，不拋，避免逃逸 typed error）、Node `Buffer.byteLength(,'utf8')`、Python `encode('utf-8','surrogatepass')`、PHP `strlen`（本即 bytes）。新增凍結迴歸向量 `rej-too-long-utf8`（非 ASCII 撐爆 byte 但 code-unit <512；PROVENANCE append 紀錄）。四語言＋跨語言矩陣＋各語言迴歸測試全綠。

**#2 PHP debug hook 雙重門檻**：`ARGONGUARD_TEST_FORCE_PROVIDER` 現同時要求測試 bootstrap 定義的 `ARGONGUARD_TESTING` 常數。生產部署無此常數，誤設 env 不生效。

**#3 Node 原型鏈**：`PROFILES` 由物件字面量改 `Map`（`Map.get` 不受原型鏈污染，未知 key 一律 undefined）。加 5 個原型鏈鍵的迴歸測試。

## 明文接受（記錄理由）

**#4 PHP Native provider 重解析**：`NativeArgon2Provider` 以 `password_verify($password, $encoded)` 驗證，libargon2 會重新解析 `$encoded`。表面上「政策檢查的 parsed 值」與「實際計算依據」是同一字串的兩次解析。**接受理由**：(a) dispatch 已先以嚴格 parser 解析同一字串且政策通過，`password_verify` 對同一字串必解析出相同參數（否則嚴格 parser 有 bug，會被凍結向量抓到）；(b) PHP 原生無 argon2id raw-tag API，`password_verify` 是唯一原生介面——改走 raw 重算須強制依賴 ext-sodium，代價高於效益且縮小相容環境；(c) 無實際繞過路徑（兩次解析輸入相同）。此為 PHP 原生 API 形狀限制，非可利用弱點。sodium provider 路徑則已用 parsed 值 raw 重算。

## 端對端破壞性驗證（實際執行，非僅測試）

審查 agent 對四語言已建置產物實測：空密碼／1024-1025 byte 邊界／NUL／unpaired surrogate／emoji×N／CJK×N／salt 竄改／tag 竄改／格式破壞／keyid-data 注入／降級參數／原型鏈鍵——全部行為符合 SPEC；#1 的跨語言分歧在修復後複驗消失。

## 殘餘風險

- **PHP byte 語意（#6）**：SPEC §5 I4 明文決定 PHP 以 byte string 處理密碼、不做 well-formed 檢查。混語言 fleet 中，同一 lone-surrogate 密碼在 PHP（byte passthrough）與 .NET/Node/Python（拒絕）行為不同。屬**已知設計取捨**，M6 文件明列。無安全降級（PHP 端仍正確雜湊其收到的 bytes）。
- 全部殘餘風險 severity ≤ low；依 M5 DoD，high 以上才需 Aiken 知情，本輪無此類。

## 結論

無 critical/high；三項 code 修正完成並迴歸測試釘死，四項文件/接受處置。所有 CI（四語言 conformance 雙 TFM、守門 1、4×4 矩陣、harness 契約、nightly）綠。M5 通過。
