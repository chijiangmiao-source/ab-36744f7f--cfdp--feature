"""CFDP Class 2 闭环审计 HTTP 服务（仅标准库）。

路由：
  GET  /healthz                       健康响应
  POST /audit                         提交捕获 {audit_id, capture:[base64...]}
  GET  /audit/{audit_id}              读取冻结裁决
  POST /audit/{audit_id}/repair       针对冻结为 incomplete 的来源提交补帧
                                      试算 {repair_id, supplement:[base64...]}
  GET  /audit/{audit_id}/repair/{rid} 读取冻结的补帧试算结果

提交语义：
  新标识                → 201 result=frozen，裁决冻结
  同标识 + 完全相同输入 → 200 result=replayed，返回原冻结结果
  同标识 + 输入改变     → 409 result=conflict（原审计：原始捕获改变；
                          补帧试算：换来源 / 来源捕获变 / 任一补帧变）
"""

from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

from . import audit as audit_mod
from . import repair as repair_mod
from .store import CaptureError, VerdictStore, decode_capture

REPAIR_POST_RE = re.compile(r"^/audit/([^/]+)/repair/?$")
REPAIR_GET_RE = re.compile(r"^/audit/([^/]+)/repair/([^/]+)/?$")


class _State:
    def __init__(self) -> None:
        self.store = VerdictStore()
        self.lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _verdict_summary(v: dict) -> dict:
    return {
        "verdict": v.get("verdict"),
        "transaction": v.get("transaction"),
        "frozen": v.get("frozen"),
        "phase": v.get("phase"),
        "first_violation": v.get("first_violation"),
        "pdu_count": v.get("pdu_count"),
    }


class Handler(BaseHTTPRequestHandler):
    state: _State = _State()
    server_version = "CFDPAuditor/1.0"

    # ------------------------------------------------ 工具
    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        if os.environ.get("CFDP_AUDIT_QUIET"):
            return
        super().log_message(fmt, *args)

    # ------------------------------------------------ GET
    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/healthz":
            self._json(HTTPStatus.OK, {
                "status": "ok",
                "service": "cfdp-class2-auditor",
                "time": _now(),
            })
            return

        m = REPAIR_GET_RE.match(path)
        if m:
            audit_id = unquote(m.group(1))
            repair_id = unquote(m.group(2))
            entry = self.state.store.get_repair(repair_id)
            if entry is None or entry.source_audit_id != audit_id:
                self._json(HTTPStatus.NOT_FOUND, {
                    "error": "repair_id_not_found",
                    "audit_id": audit_id,
                    "repair_id": repair_id,
                })
                return
            self._json(HTTPStatus.OK, {
                "audit_id": audit_id,
                "repair_id": repair_id,
                "result": "frozen",
                "frozen_at": entry.result.get("frozen_at"),
                "repair": entry.result,
            })
            return

        if path.startswith("/audit/"):
            audit_id = unquote(path[len("/audit/"):])
            if not audit_id or "/" in audit_id:
                self._json(HTTPStatus.NOT_FOUND,
                           {"error": "not_found"})
                return
            entry = self.state.store.get(audit_id)
            if entry is None:
                self._json(HTTPStatus.NOT_FOUND, {
                    "error": "audit_id_not_found",
                    "audit_id": audit_id,
                })
                return
            self._json(HTTPStatus.OK, {
                "audit_id": audit_id,
                "result": "frozen",
                "frozen_at": entry.verdict.get("frozen_at"),
                "verdict": entry.verdict,
            })
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not_found", "path": path})

    # ------------------------------------------------ POST
    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        m = REPAIR_POST_RE.match(path)
        if m:
            self._handle_repair(unquote(m.group(1)))
            return
        if path != "/audit":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return

        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(HTTPStatus.BAD_REQUEST,
                       {"error": "invalid_json"})
            return
        if not isinstance(payload, dict):
            self._json(HTTPStatus.BAD_REQUEST,
                       {"error": "invalid_payload"})
            return

        audit_id = payload.get("audit_id")
        if not isinstance(audit_id, str) or not audit_id.strip():
            self._json(HTTPStatus.BAD_REQUEST,
                       {"error": "missing_audit_id"})
            return
        audit_id = audit_id.strip()

        try:
            frames = decode_capture(payload.get("capture"))
        except CaptureError as exc:
            self._json(HTTPStatus.BAD_REQUEST,
                       {"error": "invalid_capture", "detail": str(exc)})
            return

        # 裁决只依赖捕获内容；计算与冻结在锁外完成，冻结提交原子化。
        verdict = audit_mod.Auditor().run(frames).to_dict()

        entry, created, conflict = self.state.store.submit(
            audit_id, frames, verdict)
        if conflict is not None:
            self._json(HTTPStatus.CONFLICT, {
                "audit_id": audit_id,
                "result": "conflict",
                "error": "capture_conflict",
                "detail": "相同审计标识的原始捕获已改变"
                          "（任一方向或原始 PDU 改变即冲突）",
                "original": _verdict_summary(conflict.verdict),
                "original_pdu_count": conflict.pdu_count,
                "submitted_pdu_count": len(frames),
            })
            return

        if created:
            entry.verdict["frozen_at"] = _now()
            self._json(HTTPStatus.CREATED, {
                "audit_id": audit_id,
                "result": "frozen",
                "frozen_at": entry.verdict["frozen_at"],
                "verdict": entry.verdict,
            })
        else:
            self._json(HTTPStatus.OK, {
                "audit_id": audit_id,
                "result": "replayed",
                "frozen_at": entry.verdict.get("frozen_at"),
                "verdict": entry.verdict,
            })

    # ------------------------------------------------ 补帧试算
    def _handle_repair(self, audit_id: str) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(HTTPStatus.BAD_REQUEST,
                       {"error": "invalid_json"})
            return
        if not isinstance(payload, dict):
            self._json(HTTPStatus.BAD_REQUEST,
                       {"error": "invalid_payload"})
            return

        repair_id = payload.get("repair_id")
        if not isinstance(repair_id, str) or not repair_id.strip():
            self._json(HTTPStatus.BAD_REQUEST,
                       {"error": "missing_repair_id"})
            return
        repair_id = repair_id.strip()

        try:
            patch_frames = decode_capture(payload.get("supplement"))
        except CaptureError as exc:
            self._json(HTTPStatus.BAD_REQUEST,
                       {"error": "invalid_supplement", "detail": str(exc)})
            return

        source = self.state.store.get(audit_id)
        if source is None:
            self._json(HTTPStatus.NOT_FOUND, {
                "error": "audit_id_not_found",
                "audit_id": audit_id,
            })
            return

        result = repair_mod.build_repair_result(source, patch_frames)

        entry, created, conflict, why = self.state.store.submit_repair(
            repair_id, audit_id, source.cap_hash, patch_frames, result,
            source.pdu_count)
        if conflict is not None:
            self._json(HTTPStatus.CONFLICT, {
                "audit_id": audit_id,
                "repair_id": repair_id,
                "result": "conflict",
                "error": why,
                "detail": {
                    "repair_source_changed":
                        "该修复标识已绑定其他来源审计",
                    "source_capture_changed":
                        "来源审计的冻结捕获与首次试算时不一致",
                    "supplement_pdus_changed":
                        "相同修复标识的补帧序列已改变"
                        "（任一原始补帧改变即冲突）",
                }.get(why, "修复输入与首次冻结时不一致"),
                "original": conflict.result,
                "original_patch_pdu_count": conflict.patch_pdu_count,
                "submitted_patch_pdu_count": len(patch_frames),
            })
            return

        if created:
            entry.result["frozen_at"] = _now()
            self._json(HTTPStatus.CREATED, {
                "audit_id": audit_id,
                "repair_id": repair_id,
                "result": "frozen",
                "frozen_at": entry.result["frozen_at"],
                "repair": entry.result,
            })
        else:
            self._json(HTTPStatus.OK, {
                "audit_id": audit_id,
                "repair_id": repair_id,
                "result": "replayed",
                "frozen_at": entry.result.get("frozen_at"),
                "repair": entry.result,
            })


def build_server(host: str, port: int) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), Handler)


def main(argv: list[str] | None = None) -> int:
    host = os.environ.get("CFDP_AUDIT_HOST", "0.0.0.0")
    port = int(os.environ.get("CFDP_AUDIT_PORT", "8080"))
    httpd = build_server(host, port)
    print(f"CFDP Class 2 auditor listening on {host}:{port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
