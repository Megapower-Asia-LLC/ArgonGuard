# ArgonGuard Spec

語言中立規格與凍結測試向量（M1 產出）。此目錄是四語言實作的唯一權威來源：

- `SPEC.md` — normative 規格（RFC 2119）
- `reason-codes.json` — reason code 權威枚舉
- `engine-units.json` — 引擎 memory 單位對照與期望常數
- `harness-contract.json` — dev harness I/O 凍結 fixture（M2 產出）
- `reference/dotnet-baseline.md` — .NET 參考實作 baseline freeze 宣告（M2 產出）
- `vectors/v1/` — 五類凍結向量＋`MANIFEST.sha256`＋`PROVENANCE.md`（append-only；修正走 v1→v2 重凍程序）
