#!/usr/bin/env python3
"""ArgonGuard dev harness（協議凍結於 spec/harness-contract.json，schemaVersion 1）。

stdin 單一 JSON：``{"schemaVersion":1,"commands":[…]}``
stdout 單行 JSON：``{"schemaVersion":1,"results":[…]}``
ops：hash{profile,passwordHex}／verify{passwordHex,encoded}／
     needsRehash{activeProfile,encoded,legacyRegistered?}
結果：成功 ``{"ok":true,"encoded":…}`` 或 ``{"ok":true,"value":bool}``；
typed error ``{"ok":false,"error":"<類別名>","reason":"<reason code>"}``
（error 名＝五類別名，無後綴）。
"""

import json
import sys
from pathlib import Path

# venv 外直接執行時的 fallback（editable install 下非必要，但無害）
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from argonguard.passwords import (  # noqa: E402
    ArgonGuardError,
    ArgonGuardPasswordHasher,
    ArgonGuardProfile,
)


class BcryptPrefixClaimer(object):
    """harness 協議中 legacyRegistered=true 的標準認領器（與向量語意一致）。"""

    def can_handle(self, encoded_hash):
        return encoded_hash.startswith("$2b$")

    def verify(self, password, encoded_hash):
        return False


def run_command(command):
    try:
        op = command.get("op")
        if op == "hash":
            hasher = ArgonGuardPasswordHasher(ArgonGuardProfile(command["profile"]))
            return {"ok": True, "encoded": hasher.hash_password(_utf8(command["passwordHex"]))}
        if op == "verify":
            hasher = ArgonGuardPasswordHasher()
            return {"ok": True,
                    "value": hasher.verify_password(_utf8(command["passwordHex"]),
                                                    command["encoded"])}
        if op == "needsRehash":
            legacy = (BcryptPrefixClaimer(),) if command.get("legacyRegistered") else ()
            hasher = ArgonGuardPasswordHasher(
                ArgonGuardProfile(command["activeProfile"]), legacy)
            return {"ok": True, "value": hasher.needs_rehash(command["encoded"])}
        return {"ok": False, "error": "HarnessError", "reason": "unknown_op"}
    except ArgonGuardError as exc:
        return {"ok": False, "error": exc.category, "reason": exc.reason}


def _utf8(hex_string):
    return bytes.fromhex(hex_string).decode("utf-8")


def main():
    request = json.loads(sys.stdin.read())
    if request.get("schemaVersion") != 1:
        sys.stderr.write("unsupported schemaVersion\n")
        return 2
    results = [run_command(command) for command in request.get("commands", [])]
    sys.stdout.write(json.dumps({"schemaVersion": 1, "results": results}))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
