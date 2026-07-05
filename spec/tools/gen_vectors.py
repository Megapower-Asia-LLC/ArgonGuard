#!/usr/bin/env python3
"""ArgonGuard 凍結向量產生器（M1-T3/T4/T5）。

凍結規則（同源條款升級版，見 PROVENANCE.md）：
- 每筆 tag 必須由兩個「彼此獨立的實作」一致產生：
  argon2-cffi（phc-winner-argon2 C 參考實作）× RustCrypto argon2（@node-rs/argon2）
- encoded 字串由 cffi 產生，機械回解驗證每個欄位（v=19、m,t,p 順序、無 padding b64、salt/tag bytes）
- argon2 reference CLI 對其能力範圍內的子集（密碼 ≤127 bytes、salt 無 NUL）做第三重交叉比對
- ArgonGuard 自家實作不得參與（SPEC §10）

用法：python3 gen_vectors.py <output-dir>
"""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from argon2 import low_level

ARGON2_CLI = "argon2"

# ---- 檔位（與 spec/engine-units.json 一致；此處為產生工具的輸入，非權威）----
PROFILES = {
    "default": {"m": 19456, "t": 2, "p": 1},
    "high": {"m": 65536, "t": 2, "p": 1},
    "highest": {"m": 131072, "t": 2, "p": 1},
}
TAG_LEN = 32
SALT16 = bytes.fromhex("41726f6e47756172645631533031"+"2121")  # 'ArgonGuardV1S01!!' 前 16 bytes
SALT16_B = bytes.fromhex("00ff10e0075defacedb0deadbeef1337")   # 二進位 salt（含高位/低位 bytes，無 NUL 不可能→CLI argv 不允許 NUL，改用無 NUL 版本）
SALT16_B = bytes.fromhex("f1ff10e0075defacedb0deadbeef1337")   # 修正：首 byte 非 0x00（argv 不能含 NUL）
SALT32 = bytes.fromhex("aa55" * 16)                             # 32-byte salt（政策允許 16..64）
SALT8 = b"12345678"                                             # 8-byte salt（低於政策下限，reject 用）

# ---- 密碼集（passwordHex 為 normative）----
PASSWORDS = {
    "ascii": "password".encode(),
    "phrase": "correct horse battery staple".encode(),
    "cjk": "密碼測試".encode(),
    "emoji": "🔐🛡pass".encode(),
    "nfc": "café".encode(),               # café NFC（0xC3 0xA9）
    "nfd": "café".encode(),              # café NFD（e + U+0301）
    "min1": b"a",
    "max1024": ("測" * 341).encode() + b"a",   # 341*3+1 = 1024 bytes（多 byte 組成的上限案例）
}
assert len(PASSWORDS["max1024"]) == 1024

DUMMY_PASSWORD = b"argonguard-canonical-dummy-v1"


import base64

TOOLS_DIR = Path(__file__).parent
CLI_CHECKED = {"count": 0}


def _b64nopad(data: bytes) -> str:
    return base64.b64encode(data).decode().rstrip("=")


def cli_hash(password: bytes, salt: bytes, m: int, t: int, p: int, tag_len: int) -> str:
    """argon2 reference CLI（第三重交叉比對）。限制：密碼 ≤127 bytes、salt 無 NUL。"""
    out = subprocess.run(
        [ARGON2_CLI, salt, "-id", "-t", str(t), "-k", str(m), "-p", str(p), "-l", str(tag_len), "-e"],
        input=password, capture_output=True, check=True,
    )
    return out.stdout.decode().strip()


def rust_raw(password: bytes, salt: bytes, m: int, t: int, p: int, tag_len: int) -> str:
    """RustCrypto（@node-rs/argon2）獨立實作，回傳 raw tag hex。"""
    job = [{"passwordHex": password.hex(), "saltHex": salt.hex(), "m": m, "t": t, "p": p, "tagLen": tag_len}]
    out = subprocess.run(["node", str(TOOLS_DIR / "rust_hash.mjs")],
                         input=json.dumps(job).encode(), capture_output=True, check=True)
    return json.loads(out.stdout)[0]


def _verify_encoding(enc: str, salt: bytes, tag_hex: str, m: int, t: int, p: int) -> None:
    """機械回解 encoded 欄位（非第二實作，純結構驗證）。"""
    parts = enc.split("$")
    assert parts[0] == "" and parts[1] == "argon2id" and parts[2] == "v=19", enc
    assert parts[3] == f"m={m},t={t},p={p}", enc
    assert parts[4] == _b64nopad(salt) and "=" not in parts[4], enc
    assert parts[5] == _b64nopad(bytes.fromhex(tag_hex)) and "=" not in parts[5], enc


def dual(password: bytes, salt: bytes, m: int, t: int, p: int, tag_len: int = TAG_LEN) -> str:
    """獨立雙實作（cffi × RustCrypto）一致才凍結；CLI 能力範圍內做第三重比對。"""
    enc = low_level.hash_secret(password, salt, time_cost=t, memory_cost=m, parallelism=p,
                                hash_len=tag_len, type=low_level.Type.ID, version=19).decode()
    raw_cffi = low_level.hash_secret_raw(password, salt, time_cost=t, memory_cost=m, parallelism=p,
                                         hash_len=tag_len, type=low_level.Type.ID, version=19).hex()
    raw_rust = rust_raw(password, salt, m, t, p, tag_len)
    if raw_cffi != raw_rust:
        raise SystemExit(f"FREEZE GATE FAILURE: cffi vs RustCrypto tag mismatch\n  cffi: {raw_cffi}\n  rust: {raw_rust}")
    _verify_encoding(enc, salt, raw_cffi, m, t, p)
    if len(password) <= 127 and b"\x00" not in salt:
        c = cli_hash(password, salt, m, t, p, tag_len)
        if c != enc:
            raise SystemExit(f"FREEZE GATE FAILURE: CLI vs cffi encoded mismatch\n  CLI : {c}\n  cffi: {enc}")
        CLI_CHECKED["count"] += 1
    return enc


def main(outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    meta = {"specVersion": "1.0.0", "frozen": True}

    # ---- deterministic.json ----
    det = []
    for pname, pw in PASSWORDS.items():
        for prof, prm in PROFILES.items():
            det.append({
                "id": f"det-{pname}-{prof}",
                "passwordHex": pw.hex(),
                "saltHex": SALT16.hex(),
                "m": prm["m"], "t": prm["t"], "p": prm["p"], "tagLen": TAG_LEN,
                "profile": prof,
                "encoded": dual(pw, SALT16, prm["m"], prm["t"], prm["p"]),
            })
    # 二進位 salt 案例（default 檔位）
    det.append({
        "id": "det-ascii-default-binsalt",
        "passwordHex": PASSWORDS["ascii"].hex(), "saltHex": SALT16_B.hex(),
        "m": 19456, "t": 2, "p": 1, "tagLen": TAG_LEN, "profile": "default",
        "encoded": dual(PASSWORDS["ascii"], SALT16_B, 19456, 2, 1),
    })

    # ---- verify.json ----
    ver = []
    # frontier 通過案例（policy-pass、非檔位參數）
    for vid, m, t in [("t1-owasp", 47104, 1), ("t5-floor", 7168, 5), ("t8-ceiling", 7168, 8)]:
        enc = dual(PASSWORDS["ascii"], SALT16, m, t, 1)
        ver.append({"id": f"ver-{vid}-ok", "passwordHex": PASSWORDS["ascii"].hex(),
                    "encoded": enc, "expected": True,
                    "note": f"OWASP frontier/ceiling pass (m={m},t={t})"})
    # 較長 salt / tag（政策範圍內）
    ver.append({"id": "ver-salt32-ok", "passwordHex": PASSWORDS["ascii"].hex(),
                "encoded": dual(PASSWORDS["ascii"], SALT32, 19456, 2, 1), "expected": True,
                "note": "32-byte salt within [16,64]"})
    ver.append({"id": "ver-tag64-ok", "passwordHex": PASSWORDS["ascii"].hex(),
                "encoded": dual(PASSWORDS["ascii"], SALT16, 19456, 2, 1, tag_len=64), "expected": True,
                "note": "64-byte tag within [32,128]"})
    # 錯誤密碼 → false
    base = det[0]["encoded"]
    ver.append({"id": "ver-wrong-password", "passwordHex": b"wrongpass".hex(),
                "encoded": base, "expected": False, "note": "verify false has exactly one meaning"})
    # salt 竄改 → false（OWASP 筆記 §5.3 邊界案例）
    parts = base.split("$")  # ['', 'argon2id', 'v=19', 'm=..', salt, tag]
    tampered_salt = parts[:]
    tampered_salt[4] = ("A" if parts[4][0] != "A" else "B") + parts[4][1:]
    ver.append({"id": "ver-tampered-salt", "passwordHex": PASSWORDS["ascii"].hex(),
                "encoded": "$".join(tampered_salt), "expected": False, "note": "tampered salt → recompute mismatch"})
    tampered_tag = parts[:]
    tampered_tag[5] = ("A" if parts[5][0] != "A" else "B") + parts[5][1:]
    ver.append({"id": "ver-tampered-tag", "passwordHex": PASSWORDS["ascii"].hex(),
                "encoded": "$".join(tampered_tag), "expected": False, "note": "tampered tag → mismatch"})
    # NFC 密碼對 NFD hash → false（不做正規化的證明）
    ver.append({"id": "ver-nfc-vs-nfd", "passwordHex": PASSWORDS["nfc"].hex(),
                "encoded": next(d["encoded"] for d in det if d["id"] == "det-nfd-default"),
                "expected": False, "note": "no Unicode normalization: NFC input vs NFD-derived hash"})

    # ---- reject.json ----
    rej = []

    def crafted(m=19456, t=2, p=1, v="v=19$", salt_b64=None, tag_b64=None, params=None, prefix="$argon2id$"):
        import base64
        s = salt_b64 if salt_b64 is not None else base64.b64encode(SALT16).decode().rstrip("=")
        g = tag_b64 if tag_b64 is not None else base64.b64encode(b"\x11" * TAG_LEN).decode().rstrip("=")
        pr = params if params is not None else f"m={m},t={t},p={p}"
        return f"{prefix}{v}{pr}${s}${g}"

    def R(rid, encoded, err, reason, note):
        rej.append({"id": rid, "passwordHex": PASSWORDS["ascii"].hex(), "encoded": encoded,
                    "expectedError": err, "expectedReason": reason, "note": note})

    # frontier / 天花板（真實產生，政策在重算前拒絕，但真實 hash 更乾淨）
    R("rej-frontier-7167-t5", dual(PASSWORDS["ascii"], SALT16, 7167, 5, 1),
      "PolicyViolation", "policy_violation.below_owasp_frontier", "frontier boundary (7167,5)")
    R("rej-frontier-18432-t2", dual(PASSWORDS["ascii"], SALT16, 18432, 2, 1),
      "PolicyViolation", "policy_violation.below_owasp_frontier", "below (19456,2)")
    R("rej-frontier-46080-t1", dual(PASSWORDS["ascii"], SALT16, 46080, 1, 1),
      "PolicyViolation", "policy_violation.below_owasp_frontier", "below t=1 floor 47104")
    R("rej-t9-above-ceiling", dual(PASSWORDS["ascii"], SALT16, 7168, 9, 1),
      "PolicyViolation", "policy_violation.t_above_ceiling", "ceiling boundary (7168,9)")
    R("rej-m-above-ceiling", crafted(m=262208), "PolicyViolation", "policy_violation.m_above_ceiling",
      "m>262144 rejected before recompute (crafted tag; policy precedes recompute)")
    R("rej-p2", crafted(p=2), "PolicyViolation", "policy_violation.p_not_one", "p=2 (crafted)")
    R("rej-missing-v", crafted(v=""), "PolicyViolation", "policy_violation.missing_version", "missing v field")
    R("rej-v16", crafted(v="v=16$"), "PolicyViolation", "policy_violation.unsupported_version", "v=16")
    R("rej-keyid", crafted(params="m=19456,t=2,p=1,keyid=Zm9v"), "PolicyViolation",
      "policy_violation.keyid_not_allowed", "keyid present")
    R("rej-data", crafted(params="m=19456,t=2,p=1,data=Zm9v"), "PolicyViolation",
      "policy_violation.data_not_allowed", "data present")
    R("rej-salt8", dual(PASSWORDS["ascii"], SALT8, 19456, 2, 1),
      "PolicyViolation", "policy_violation.salt_length_out_of_range", "8-byte salt < 16")
    import base64 as _b64
    R("rej-salt72", crafted(salt_b64=_b64.b64encode(b"\x22" * 72).decode().rstrip("=")),
      "PolicyViolation", "policy_violation.salt_length_out_of_range", "72-byte salt > 64 (crafted)")
    R("rej-tag16", dual(PASSWORDS["ascii"], SALT16, 19456, 2, 1, tag_len=16),
      "PolicyViolation", "policy_violation.tag_length_out_of_range", "16-byte tag < 32")
    R("rej-tag136", crafted(tag_b64=_b64.b64encode(b"\x33" * 136).decode().rstrip("=")),
      "PolicyViolation", "policy_violation.tag_length_out_of_range", "136-byte tag > 128 (crafted)")
    # malformed
    R("rej-b64-padding", crafted(salt_b64=_b64.b64encode(SALT16).decode()),  # 帶 '=' padding
      "MalformedHash", "malformed.bad_base64", "padded base64 MUST be rejected")
    R("rej-b64-url-alphabet", crafted(tag_b64="-_" + _b64.b64encode(b"\x11" * TAG_LEN).decode().rstrip("=")[2:]),
      "MalformedHash", "malformed.bad_base64", "base64url alphabet")
    R("rej-params-out-of-order", crafted(params="t=2,m=19456,p=1"),
      "MalformedHash", "malformed.params_out_of_order", "t before m")
    R("rej-too-long", crafted(tag_b64="A" * 480), "MalformedHash", "malformed.encoded_too_long",
      ">512 chars pre-check before parse")
    R("rej-not-phc", "not-a-hash-at-all", "MalformedHash", "malformed.not_phc", "garbage input")
    R("rej-empty", "", "MalformedHash", "malformed.not_phc", "empty encoded string")
    # unsupported algorithm
    a2i = low_level.hash_secret(PASSWORDS["ascii"], SALT16, 2, 19456, 1, TAG_LEN, low_level.Type.I, 19).decode()
    R("rej-argon2i", a2i, "UnsupportedAlgorithm", "unsupported.algorithm", "argon2i (real hash, wrong algorithm)")
    a2d = low_level.hash_secret(PASSWORDS["ascii"], SALT16, 2, 19456, 1, TAG_LEN, low_level.Type.D, 19).decode()
    R("rej-argon2d", a2d, "UnsupportedAlgorithm", "unsupported.algorithm", "argon2d")
    R("rej-bcrypt", "$2b$12$LQVkVYq1S7Ck1MQIViYyNOG3Fabe/y0BB6kJ1O8ZQNXY9nCzC1jU6",
      "UnsupportedAlgorithm", "unsupported.algorithm", "bcrypt without registered legacy verifier")

    # ---- needs-rehash.json（truth table）----
    nr_meta = "needsRehash(encoded) 相對 activeProfile 的 truth table；legacyRegistered 表示是否註冊了認領 $2b$ 的 legacy verifier"
    enc_default = next(d["encoded"] for d in det if d["id"] == "det-ascii-default")
    enc_high = next(d["encoded"] for d in det if d["id"] == "det-ascii-high")
    enc_highest = next(d["encoded"] for d in det if d["id"] == "det-ascii-highest")
    enc_t1 = next(v["encoded"] for v in ver if v["id"] == "ver-t1-owasp-ok")
    enc_salt32 = next(v["encoded"] for v in ver if v["id"] == "ver-salt32-ok")
    nr = [
        {"id": "nr-exact-default", "encoded": enc_default, "activeProfile": "default", "legacyRegistered": False, "expected": False, "note": "exact match"},
        {"id": "nr-exact-high", "encoded": enc_high, "activeProfile": "high", "legacyRegistered": False, "expected": False, "note": "exact match"},
        {"id": "nr-exact-highest", "encoded": enc_highest, "activeProfile": "highest", "legacyRegistered": False, "expected": False, "note": "exact match"},
        {"id": "nr-stronger-than-active", "encoded": enc_high, "activeProfile": "default", "legacyRegistered": False, "expected": True, "note": "stronger also true (converge to single set)"},
        {"id": "nr-weaker-than-active", "encoded": enc_default, "activeProfile": "high", "legacyRegistered": False, "expected": True, "note": "weaker true"},
        {"id": "nr-offlist-owasp", "encoded": enc_t1, "activeProfile": "default", "legacyRegistered": False, "expected": True, "note": "(47104,1,1) differs from active"},
        {"id": "nr-salt-len-differs", "encoded": enc_salt32, "activeProfile": "default", "legacyRegistered": False, "expected": True, "note": "salt length differs from profile"},
        {"id": "nr-legacy-claimed", "encoded": "$2b$12$LQVkVYq1S7Ck1MQIViYyNOG3Fabe/y0BB6kJ1O8ZQNXY9nCzC1jU6", "activeProfile": "default", "legacyRegistered": True, "expected": True, "note": "legacy claimed → always true"},
        {"id": "nr-legacy-unclaimed-nonargon2id", "encoded": "$2b$12$LQVkVYq1S7Ck1MQIViYyNOG3Fabe/y0BB6kJ1O8ZQNXY9nCzC1jU6", "activeProfile": "default", "legacyRegistered": False, "expected": {"error": "UnsupportedAlgorithm", "reason": "unsupported.algorithm"}, "note": "parseable-as-non-argon2id, unclaimed"},
        {"id": "nr-garbage-unclaimed", "encoded": "corrupted-data", "activeProfile": "default", "legacyRegistered": False, "expected": {"error": "MalformedHash", "reason": "malformed.not_phc"}, "note": "corruption must not fold into true"},
    ]

    # ---- input-limits.json ----
    il = [
        {"id": "il-empty", "passwordHex": "", "appliesTo": "all", "expected": {"error": "InvalidInput", "reason": "invalid_input.password_empty"}, "note": "empty password"},
        {"id": "il-min-1byte", "passwordHex": b"a".hex(), "appliesTo": "all", "expected": "ok", "note": "1 byte minimum"},
        {"id": "il-1024-multibyte", "passwordHex": PASSWORDS["max1024"].hex(), "appliesTo": "all", "expected": "ok", "note": "exactly 1024 bytes composed of multi-byte chars"},
        {"id": "il-1025", "passwordHex": (b"a" * 1025).hex(), "appliesTo": "all", "expected": {"error": "InvalidInput", "reason": "invalid_input.password_too_long"}, "note": "1025 bytes"},
        {"id": "il-nul", "passwordHex": b"pass\x00word".hex(), "appliesTo": "all", "expected": {"error": "InvalidInput", "reason": "invalid_input.password_contains_nul"}, "note": "U+0000"},
        {"id": "il-surrogate", "stringInput": "\\uD800ab", "appliesTo": "string-apis", "expected": {"error": "InvalidInput", "reason": "invalid_input.password_not_well_formed"}, "note": "unpaired surrogate; PHP byte semantics exempt"},
        {"id": "il-nfc-nfd-differ", "refA": "det-nfc-default", "refB": "det-nfd-default", "appliesTo": "all", "expected": "hashes-differ", "note": "no normalization: NFC and NFD produce different hashes"},
    ]

    # ---- dummy-hashes.json ----
    dh = [{"profile": prof, "passwordHex": DUMMY_PASSWORD.hex(),
           "encoded": dual(DUMMY_PASSWORD, SALT16, prm["m"], prm["t"], prm["p"])}
          for prof, prm in PROFILES.items()]

    # ---- 寫檔＋MANIFEST ----
    files = {
        "deterministic.json": {**meta, "entries": det},
        "verify.json": {**meta, "entries": ver},
        "reject.json": {**meta, "entries": rej},
        "needs-rehash.json": {**meta, "description": nr_meta, "entries": nr},
        "input-limits.json": {**meta, "entries": il},
        "dummy-hashes.json": {**meta, "entries": dh},
    }
    manifest_lines = []
    for name, payload in files.items():
        raw = json.dumps(payload, ensure_ascii=False, indent=2).encode() + b"\n"
        (outdir / name).write_bytes(raw)
        manifest_lines.append(f"{hashlib.sha256(raw).hexdigest()}  {name}")
    (outdir / "MANIFEST.sha256").write_text("\n".join(manifest_lines) + "\n")
    print(f"frozen {sum(len(p['entries']) for p in files.values())} entries across {len(files)} files")
    print(f"CLI third-source cross-checked entries: {CLI_CHECKED['count']}")
    print((outdir / "MANIFEST.sha256").read_text())


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "../vectors/v1"))
