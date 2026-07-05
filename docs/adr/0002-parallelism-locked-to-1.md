# ADR 0002：全檔位 parallelism 鎖定 p=1

**狀態**：Accepted（設計審核 round 3 共識，2026-07-05）

## 背景

libsodium 的 `crypto_pwhash` 家族不暴露 parallelism 參數（計算固定 threads=1，已查證 doc.libsodium.org）。受影響路徑：PHP ext-sodium fallback、未來 .NET 換 libsodium 系引擎（Geralt/NSec）的選項。

## 決策

三個強度檔位（default/high/highest）全部 p=1；驗證端政策要求 `p==1`（p>1 的外部存量走 legacy verifier 顯式 opt-in）。強度僅以 memory 為旋鈕（19→64→128 MiB）。

## 理由

p=1 是四語言（含 libsodium 系 provider）能同時「產生與驗證」的唯一安全交集；OWASP 等效最低配置清單全部 p=1，無合規損失。

## 後果

- PHP sodium fallback 與未來引擎替換不會遇到參數不支援問題。
- Django（p=8）等外部存量需 legacy verifier 認領——刻意的可見 opt-in，非預設放行。
- 若未來要開放 p>1，屬 spec MAJOR 等級決策，需重新評估全引擎相容性。
