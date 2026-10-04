"""HTTP 冒烟：向运行中的审计服务提交一个完整 CFDP Class 2 闭环捕获。

用法: python smoke.py [base_url]
成功以退出码 0 结束，任何断言失败退出码非 0。
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

from app import cfdp
from tests.helpers import ENTITY, SEQ


def _request(method: str, url: str, payload=None) -> tuple[int, dict]:
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def wait_healthy(base: str, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            status, body = _request("GET", f"{base}/healthz")
            if status == 200 and body.get("status") == "ok":
                return
        except OSError as exc:
            last = exc
        time.sleep(0.3)
    raise SystemExit(f"健康检查失败: {base} ({last})")


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else \
        os.environ.get("WEB_BASE_URL", "http://127.0.0.1:8080")
    wait_healthy(base)
    print(f"[smoke] health ok @ {base}")

    payload = bytes((i * 17 + 3) & 0xFF for i in range(2048))
    frames = [
        cfdp.encode(cfdp.metadata(ENTITY, SEQ, len(payload), "smoke.dat")),
        cfdp.encode(cfdp.file_data(ENTITY, SEQ, 0, payload)),
        cfdp.encode(cfdp.eof(ENTITY, SEQ, len(payload),
                             cfdp.crc32c(payload))),
        cfdp.encode(cfdp.ack_eof(ENTITY, SEQ)),
        cfdp.encode(cfdp.finished(ENTITY, SEQ)),
        cfdp.encode(cfdp.ack_finished(ENTITY, SEQ)),
    ]
    capture = [base64.b64encode(f).decode("ascii") for f in frames]
    # 每次运行使用唯一标识，保证首轮为 frozen；同轮内再提交验证回放
    audit_id = f"smoke-closed-loop-{int(time.time())}"

    status, body = _request("POST", f"{base}/audit", {
        "audit_id": audit_id, "capture": capture})
    assert status == 201, f"提交应返回 201，实际 {status}: {body}"
    assert body["result"] == "frozen", body

    v = body["verdict"]
    assert v["verdict"] == "closed_ok", v
    frozen = v["frozen"]
    assert frozen["file_length"] == len(payload) == 2048, frozen
    assert frozen["received_length"] == 2048, frozen
    assert frozen["coverage"] == [[0, 2048]], frozen
    assert frozen["missing"] == [], frozen
    assert frozen["first_missing_offset"] is None, frozen
    assert frozen["checksum_mismatch"] is False, frozen
    assert frozen["crc32c"] == f"{cfdp.crc32c(payload):08x}", frozen

    stages = [(m["role"], m["pdu"], m["stage"])
              for m in v["phase_evidence"]]
    assert stages == [
        ("sender", "Metadata", "metadata_issued"),
        ("sender", "EOF", "eof_sent"),
        ("receiver", "ACK", "ack_eof_complete"),
        ("receiver", "Finished", "finished_complete"),
        ("receiver", "ACK", "ack_finished_closed"),
    ], stages
    print("[smoke] 闭环裁决: closed_ok，完整覆盖 [0,2048)，"
          "双方阶段证据齐备")

    # 同标识完全相同捕获 → 原冻结裁决
    status2, body2 = _request("POST", f"{base}/audit", {
        "audit_id": audit_id, "capture": capture})
    assert status2 == 200 and body2["result"] == "replayed", body2
    assert body2["verdict"] == v, "回放必须返回原冻结裁决"
    print(f"[smoke] 相同捕获回放({audit_id}): 返回原冻结裁决")

    print("[smoke] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
