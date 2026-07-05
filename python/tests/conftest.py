"""測試共用：凍結向量／權威 JSON 載入（spec/ 為唯一來源，不得複製常數進測試）。"""

import json
from pathlib import Path

SPEC_DIR = Path(__file__).resolve().parents[2] / "spec"
VECTORS_DIR = SPEC_DIR / "vectors" / "v1"


def load_spec_json(name):
    """讀取 spec/ 下的權威 JSON（如 reason-codes.json、engine-units.json）。"""
    return json.loads((SPEC_DIR / name).read_text(encoding="utf-8"))


def vector_entries(name):
    """讀取凍結向量檔的 entries。"""
    data = json.loads((VECTORS_DIR / name).read_text(encoding="utf-8"))
    return data["entries"]


def vector_entry(name, entry_id):
    """依 id 取單筆向量。"""
    for entry in vector_entries(name):
        if entry["id"] == entry_id:
            return entry
    raise KeyError("{0}: {1} not found".format(name, entry_id))


class FakeBcryptVerifier(object):
    """向量／harness 協議中 legacyRegistered=true 的標準認領器（can_handle $2b$、verify False）。"""

    def can_handle(self, encoded_hash):
        return encoded_hash.startswith("$2b$")

    def verify(self, password, encoded_hash):
        return False
