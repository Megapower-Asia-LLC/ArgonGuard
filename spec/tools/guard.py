#!/usr/bin/env python3
"""守門 1（M1-T7）：語言中立的 spec 不變式檢查。任一失敗＝建置紅燈。

檢查項：
1. MANIFEST.sha256 與 vectors/v1/*.json 逐檔一致（凍結完整性）
2. default==(19456,2,1) 永久哨兵；OWASP frontier 表逐值斷言（獨立常數副本）
3. profiles.snapshot.json append-only：快照內每筆必須原樣存在於 engine-units.json
4. sodium 單位換算：engine-units 內 sodium_memlimit_bytes == m_kib*1024；上下界常數
5. 向量檔引用的 expectedError/expectedReason 全部存在於 reason-codes.json
標準函式庫 only，無第三方依賴。
"""

import hashlib
import json
import sys
from pathlib import Path

SPEC = Path(__file__).parent.parent
FAILURES: list[str] = []


def fail(msg: str) -> None:
    FAILURES.append(msg)


def check_manifest() -> None:
    vdir = SPEC / "vectors" / "v1"
    manifest = {}
    for line in (vdir / "MANIFEST.sha256").read_text().splitlines():
        digest, name = line.split(None, 1)
        manifest[name.strip()] = digest
    for name, digest in manifest.items():
        actual = hashlib.sha256((vdir / name).read_bytes()).hexdigest()
        if actual != digest:
            fail(f"MANIFEST mismatch: {name} (frozen vectors modified in place?)")
    json_files = {p.name for p in vdir.glob("*.json")}
    unlisted = json_files - set(manifest)
    if unlisted:
        fail(f"vector files not in MANIFEST: {sorted(unlisted)}")


# OWASP frontier 獨立常數副本（查證 2026-07-05；與 engine-units.json 互相印證）
FRONTIER = {1: 47104, 2: 19456, 3: 12288, 4: 9216, 5: 7168}


def check_constants() -> None:
    eu = json.loads((SPEC / "engine-units.json").read_text())
    d = eu["profiles"]["default"]
    if not (d["m_kib"] == 19456 and d["t"] == 2 and d["p"] == 1):
        fail(f"SENTINEL BROKEN: default != (19456,2,1): {d}")
    for row in eu["verificationPolicy"]["owaspFrontier"]:
        if FRONTIER.get(row["t"]) != row["min_m_kib"]:
            fail(f"frontier mismatch at t={row['t']}: {row['min_m_kib']}")
    if len(eu["verificationPolicy"]["owaspFrontier"]) != len(FRONTIER):
        fail("frontier row count mismatch")
    ceil = eu["verificationPolicy"]["ceiling"]
    if ceil != {"max_m_kib": 262144, "max_t": 8, "maxSaltBytes": 64, "maxTagBytes": 128, "maxEncodedLength": 512}:
        fail(f"ceiling constants changed: {ceil}")
    for name, p in eu["profiles"].items():
        if p["sodium_memlimit_bytes"] != p["m_kib"] * 1024:
            fail(f"sodium unit conversion broken for profile {name}")
        if p["p"] != 1:
            fail(f"profile {name} has p != 1")
        floor = FRONTIER.get(min(p["t"], 5))
        if p["m_kib"] < floor:
            fail(f"profile {name} below OWASP frontier")
    sb = eu["verificationPolicy"]["sodiumBoundsAssertions"]
    if sb["frontier_min_memlimit_bytes"] != 7168 * 1024 or sb["ceiling_memlimit_bytes"] != 262144 * 1024:
        fail("sodium bounds assertion constants broken")


def check_snapshot_append_only() -> None:
    snap = json.loads((SPEC / "profiles.snapshot.json").read_text())
    eu = json.loads((SPEC / "engine-units.json").read_text())
    for name, sp in snap["profiles"].items():
        cur = eu["profiles"].get(name)
        if cur is None:
            fail(f"profile {name} removed (snapshot is append-only)")
            continue
        for key, val in sp.items():
            if cur.get({"m_kib": "m_kib", "t": "t", "p": "p", "saltBytes": "saltBytes", "tagBytes": "tagBytes"}[key]) != val:
                fail(f"profile {name}.{key} modified (snapshot is append-only)")


def check_reason_codes() -> None:
    rc = json.loads((SPEC / "reason-codes.json").read_text())
    valid_codes = {code for cat in rc["categories"].values() for code in cat["codes"]}
    valid_errors = set(rc["categories"])
    vdir = SPEC / "vectors" / "v1"
    for fname in ["reject.json", "needs-rehash.json", "input-limits.json"]:
        for e in json.loads((vdir / fname).read_text())["entries"]:
            exp = e.get("expected") if isinstance(e.get("expected"), dict) else None
            err = e.get("expectedError") or (exp or {}).get("error")
            reason = e.get("expectedReason") or (exp or {}).get("reason")
            if err and err not in valid_errors:
                fail(f"{fname}:{e['id']} unknown error category {err}")
            if reason and reason not in valid_codes:
                fail(f"{fname}:{e['id']} unknown reason code {reason}")
            if err and reason and reason not in rc["categories"][err]["codes"]:
                fail(f"{fname}:{e['id']} reason {reason} not in category {err}")


def main() -> int:
    for chk in (check_manifest, check_constants, check_snapshot_append_only, check_reason_codes):
        try:
            chk()
        except Exception as exc:  # 守門自身錯誤也算紅燈
            fail(f"{chk.__name__} raised: {exc!r}")
    if FAILURES:
        print("GUARD FAILURES:")
        for f in FAILURES:
            print(f"  ✗ {f}")
        return 1
    print("guard: all spec invariants hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
