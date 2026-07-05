# ADR 0001：儲存格式採標準 PHC string format

**狀態**：Accepted（設計審核 round 3 共識，2026-07-05）

## 背景

原始設計筆記提議自訂 `<param-set-id>$<salt>$<hash>` 自我描述格式。設計評審（三方案 judge panel＋Perplexity 三輪審核）比較了自訂 envelope（方案 B）、標準 PHC＋精確白名單（方案 C）與標準 PHC＋驗證端政策（方案 A）。

## 決策

採標準 PHC string format：`$argon2id$v=19$m=<m>,t=<t>,p=1$<salt-b64>$<hash-b64>`，一字不改。param-set-id 概念降格為函式庫內部檔位名（`default`/`high`/`highest`），永不落地資料庫。

## 理由

1. 四語言主流函式庫以 PHC 為原生格式（PHP `password_verify` 只吃 PHC）；自訂格式迫使四語言各寫編解碼、PHP 繞過原生 API。
2. 生態工具（hashcat、稽核、框架 rehash）直接可用；外部存量 argon2id 政策範圍內直接可驗。
3. 自訂格式唯一實質優點（downgrade 防護）由驗證端參數政策（ADR 0003）完整取回。
4. 前向相容：新增檔位不需四套件 lockstep 發版。

## 後果

- 四語言各需一份嚴格 PHC parser（spec 層自寫、共用向量釘死一致性）。
- 產生端規範：`v=19` 明確輸出、參數序 `m,t,p`、禁 keyid/data、base64 無 padding；驗證端拒 padding。
- 放棄方案 B 的「一句 SQL 全 fleet 稽核」能力；離線稽核工具列入 v1.1 backlog。
