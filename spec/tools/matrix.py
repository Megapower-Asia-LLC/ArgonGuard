#!/usr/bin/env python3
"""守門 3（M3d）：4×4 跨語言 round-trip 矩陣。

維度公式（master plan 鎖定）：16 lang-pair（4 hash × 4 verify，含自對自）×
凍結固定密碼集（來源＝spec/vectors/v1 deterministic 子集）× 三檔位；
加 needs-rehash 跨語言斷言與 frontier/t=1 邊界跨語言一致。
判準完全可重現（無隨機輸入）。

用法：python3 matrix.py（於 repo 根執行；讀各語言 HARNESS_CMD）
"""

import json
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
LANGS = ["dotnet", "node", "python", "php"]
# 凍結密碼集：deterministic 子集（id 前綴），涵蓋 ASCII/CJK/emoji/NFC/1024-byte
PASSWORD_IDS = ["ascii", "cjk", "emoji", "nfc", "max1024"]
PROFILES = ["default", "high", "highest"]


def harness_cmd(lang: str) -> list:
    return shlex.split((ROOT / lang / "HARNESS_CMD").read_text().strip())


def call(lang: str, commands: list) -> list:
    req = json.dumps({"schemaVersion": 1, "commands": commands}).encode()
    proc = subprocess.run(harness_cmd(lang), input=req, capture_output=True, cwd=ROOT)
    if proc.returncode != 0:
        raise SystemExit(f"{lang} harness exited {proc.returncode}: {proc.stderr.decode()[:400]}")
    return json.loads(proc.stdout)["results"]


def main() -> int:
    det = json.loads((ROOT / "spec/vectors/v1/deterministic.json").read_text())["entries"]
    by_id = {e["id"]: e for e in det}
    passwords = {p: by_id[f"det-{p}-default"]["passwordHex"] for p in PASSWORD_IDS}
    ver = {e["id"]: e for e in json.loads((ROOT / "spec/vectors/v1/verify.json").read_text())["entries"]}
    rej = {e["id"]: e for e in json.loads((ROOT / "spec/vectors/v1/reject.json").read_text())["entries"]}

    failures = []

    # --- 產生：每語言 15 個 hash（5 密碼 × 3 檔位）---
    produced = {}  # (hasher, pwid, profile) -> encoded
    for lang in LANGS:
        cmds = [{"op": "hash", "profile": prof, "passwordHex": passwords[p]}
                for p in PASSWORD_IDS for prof in PROFILES]
        results = call(lang, cmds)
        i = 0
        for p in PASSWORD_IDS:
            for prof in PROFILES:
                r = results[i]; i += 1
                if not r.get("ok"):
                    failures.append(f"hash {lang}/{p}/{prof}: {r}")
                else:
                    produced[(lang, p, prof)] = r["encoded"]
        print(f"  hash: {lang} 15/15")

    # --- 驗證：16 lang-pair round-trip（正確密碼 true、錯誤密碼 false）＋ needs-rehash ---
    for verifier in LANGS:
        cmds, expect, labels = [], [], []
        for hasher in LANGS:
            for p in PASSWORD_IDS:
                for prof in PROFILES:
                    enc = produced[(hasher, p, prof)]
                    cmds.append({"op": "verify", "passwordHex": passwords[p], "encoded": enc})
                    expect.append(("value", True)); labels.append(f"{hasher}->{verifier} {p}/{prof} ok")
            # 錯誤密碼（default 檔位、ascii hash、cjk 密碼）
            cmds.append({"op": "verify", "passwordHex": passwords["cjk"],
                         "encoded": produced[(hasher, "ascii", "default")]})
            expect.append(("value", False)); labels.append(f"{hasher}->{verifier} wrong-pw false")
            # needs-rehash：default hash 對 active=default → false；high hash 對 default → true
            cmds.append({"op": "needsRehash", "activeProfile": "default",
                         "encoded": produced[(hasher, "ascii", "default")]})
            expect.append(("value", False)); labels.append(f"{hasher}->{verifier} nr exact false")
            cmds.append({"op": "needsRehash", "activeProfile": "default",
                         "encoded": produced[(hasher, "ascii", "high")]})
            expect.append(("value", True)); labels.append(f"{hasher}->{verifier} nr stronger true")
        # frontier / t=1 邊界（凍結向量，跨語言一致）
        for vid in ["ver-t1-owasp-ok", "ver-t5-floor-ok", "ver-t8-ceiling-ok"]:
            e = ver[vid]
            cmds.append({"op": "verify", "passwordHex": e["passwordHex"], "encoded": e["encoded"]})
            expect.append(("value", True)); labels.append(f"{verifier} {vid}")
        for rid in ["rej-frontier-7167-t5", "rej-t9-above-ceiling"]:
            e = rej[rid]
            cmds.append({"op": "verify", "passwordHex": e["passwordHex"], "encoded": e["encoded"]})
            expect.append(("reason", e["expectedReason"])); labels.append(f"{verifier} {rid}")

        results = call(verifier, cmds)
        ok = 0
        for r, (kind, want), label in zip(results, expect, labels):
            if kind == "value":
                good = r.get("ok") is True and r.get("value") == want
            else:
                good = r.get("ok") is False and r.get("reason") == want
            if good:
                ok += 1
            else:
                failures.append(f"{label}: got {r}")
        print(f"  verify: {verifier} {ok}/{len(cmds)}")

    if failures:
        print(f"\nMATRIX FAILURES ({len(failures)}):")
        for f in failures[:40]:
            print(f"  ✗ {f}")
        return 1
    print("\n4x4 cross-language matrix: ALL GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
