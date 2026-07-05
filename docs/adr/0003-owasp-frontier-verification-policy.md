# ADR 0003：驗證端政策採 OWASP frontier 凍結常數表

**狀態**：Accepted（設計審核 round 2→3 修正共識，2026-07-05）

## 背景

驗證端需要防 downgrade（DB 竄改降級參數）與資源 DoS（竄改成巨量 m）。v2 設計原採「單調地板 m≥19456 且 t≥2」；Perplexity round 2 審核（MAJOR-1）指出：單調地板會拒絕 OWASP 明確認可的 (47104,1,1)，使「完全符合 OWASP」在驗證端不成立，且「四語言漂移防呆」論證擋不住「frontier 只是 5 行凍結常數表、可用共用向量 byte-for-byte 驗證」的反駁。

## 決策

驗證端地板採 OWASP 等效配置 piecewise frontier 凍結常數表：

| t | m 最低（KiB） |
|---|---|
| 1 | 47104 |
| 2 | 19456 |
| 3 | 12288 |
| 4 | 9216 |
| ≥5 | 7168 |

配合天花板：`m≤262144`（256 MiB）、`t≤8`、salt ≤64B、tag ≤128B、字串 ≤512 字元。另 `v==19`、`p==1`、salt ≥16B、tag ≥32B。

## 理由

- OWASP 認可的所有等效配置在核心直接可驗——「完全符合 OWASP」在產生端與驗證端都成立。
- 表隨 spec 版本凍結（記載 OWASP 查證日期），共用 reject/verify 向量釘死四語言行為；OWASP 調整清單 → spec MINOR。
- 天花板封死 DB 竄改型 verify 端記憶體 DoS。

## 後果

- frontier×天花板交疊邊界須有專門向量：(7168,5)✓ (7167,5)✗ (7168,8)✓ (7168,9)✗。
- reason code 每維度專屬（`below_owasp_frontier`、`m_above_ceiling`、`t_above_ceiling`、`salt_length_out_of_range`、`tag_length_out_of_range`、`p_not_one`）。
