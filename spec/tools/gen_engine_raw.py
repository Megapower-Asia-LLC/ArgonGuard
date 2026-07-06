#!/usr/bin/env python3
"""產生 engine-raw.json：engine-level raw hash 向量（append-only 新檔）。

補足 deterministic.json 的覆蓋缺口（PPLX edge 審核 #4）：
- deterministic.json 為 profile 導向（m/t/p/tagLen 綁 OWASP 檔位，tagLen 恆 32）
- 本檔測 provider.hashRaw 對「非檔位」參數的產出：tagLen≠32、低記憶體 edge-safe
  （m=4096，避免 Miniflare CI OOM，且驗證 edge 引擎在低記憶體下與四語言一致）

三來源凍結（argon2-cffi × RustCrypto × argon2 CLI），沿用 gen_vectors.dual 的 freeze gate。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from gen_vectors import dual  # noqa: E402

PASSWORD = b"password"
SALT = b"AronGuardV1S01!!"  # 16-byte 測試 salt（與既有向量同源）

# (id, m, t, p, tagLen)
SPECS = [
    ("eng-taglen64-high", 65536, 2, 1, 64),      # tagLen≠32（high 檔位記憶體）
    ("eng-lowmem-edge-safe", 4096, 3, 1, 32),    # 低記憶體 edge-safe（CI 不 OOM）
    ("eng-lowmem-taglen64", 4096, 3, 1, 64),     # 低記憶體 + tagLen≠32
]


def main() -> None:
    entries = []
    for id_, m, t, p, tag_len in SPECS:
        enc = dual(PASSWORD, SALT, m, t, p, tag_len)
        entries.append({
            "id": id_,
            "passwordHex": PASSWORD.hex(),
            "saltHex": SALT.hex(),
            "m": m, "t": t, "p": p, "tagLen": tag_len,
            "encoded": enc,
        })
        print(f"  {id_}: {enc}")

    out = {
        "specVersion": "1.0.0",
        "frozen": True,
        "note": "engine-level raw hash（測 provider.hashRaw 對 tagLen≠32、低記憶體 edge-safe 參數）；三來源凍結。deterministic.json 為 profile 導向，此檔補引擎層覆蓋。",
        "entries": entries,
    }
    outp = Path(__file__).parent.parent / "vectors" / "v1" / "engine-raw.json"
    outp.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n")
    print(f"wrote {outp} ({len(entries)} entries)")


if __name__ == "__main__":
    main()
