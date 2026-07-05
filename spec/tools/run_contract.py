#!/usr/bin/env python3
"""harness contract test 執行器：把 spec/harness-contract.json 餵給指定 harness 指令，逐筆驗收。

用法：python3 run_contract.py -- <harness 指令...>
例：  python3 run_contract.py -- dotnet run --project dotnet/tools/Harness
"""

import json
import subprocess
import sys
from pathlib import Path

SPEC = Path(__file__).parent.parent


def main() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        print("usage: run_contract.py -- <harness command...>")
        return 2

    contract = json.loads((SPEC / "harness-contract.json").read_text())
    request = {"schemaVersion": contract["schemaVersion"],
               "commands": [e["command"] for e in contract["entries"]]}
    proc = subprocess.run(argv, input=json.dumps(request).encode(), capture_output=True)
    if proc.returncode != 0:
        print(f"harness exited {proc.returncode}: {proc.stderr.decode()[:500]}")
        return 1
    response = json.loads(proc.stdout)
    results = response["results"]
    if len(results) != len(contract["entries"]):
        print(f"result count mismatch: {len(results)} != {len(contract['entries'])}")
        return 1

    failures = 0
    for i, (entry, result) in enumerate(zip(contract["entries"], results)):
        expect = entry["expect"]
        problems = []
        if result.get("ok") != expect["ok"]:
            problems.append(f"ok: {result.get('ok')} != {expect['ok']}")
        if "value" in expect and result.get("value") != expect["value"]:
            problems.append(f"value: {result.get('value')} != {expect['value']}")
        if "error" in expect and result.get("error") != expect["error"]:
            problems.append(f"error: {result.get('error')} != {expect['error']}")
        if "reason" in expect and result.get("reason") != expect["reason"]:
            problems.append(f"reason: {result.get('reason')} != {expect['reason']}")
        if "encodedPrefix" in expect and not str(result.get("encoded", "")).startswith(expect["encodedPrefix"]):
            problems.append(f"encoded prefix mismatch: {str(result.get('encoded'))[:40]}")
        if expect.get("selfVerify"):
            check = subprocess.run(argv, input=json.dumps({
                "schemaVersion": 1,
                "commands": [{"op": "verify", "passwordHex": entry["command"]["passwordHex"],
                              "encoded": result["encoded"]}],
            }).encode(), capture_output=True)
            v = json.loads(check.stdout)["results"][0]
            if not (v.get("ok") and v.get("value") is True):
                problems.append("selfVerify failed")
        if problems:
            failures += 1
            print(f"✗ entry {i} ({entry['command']['op']}): " + "; ".join(problems))
    if failures:
        print(f"CONTRACT FAILURES: {failures}/{len(results)}")
        return 1
    print(f"harness contract: {len(results)}/{len(results)} ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
