"""HTTP 服务端到端测试（线程内启动，标准库 urllib 客户端）。"""

import base64
import json
import threading
import unittest
import urllib.error
import urllib.request

from app import cfdp
from app.server import build_server
from tests.helpers import ENTITY, SEQ, closed_loop_frames


PAYLOAD = bytes((i * 31 + 7) & 0xFF for i in range(512))


def b64(frames):
    return [base64.b64encode(f).decode("ascii") for f in frames]


class ServerHarness:
    def __init__(self):
        self.httpd = build_server("127.0.0.1", 0)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def request(self, method, path, payload=None):
        data = None
        headers = {}
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.url(path), data=data,
                                     headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())


class TestHTTPAPI(unittest.TestCase):
    def test_health(self):
        with ServerHarness() as h:
            status, body = h.request("GET", "/healthz")
            self.assertEqual(status, 200)
            self.assertEqual(body["status"], "ok")

    def test_full_closed_loop_submit(self):
        frames, payload = closed_loop_frames(PAYLOAD)
        with ServerHarness() as h:
            status, body = h.request("POST", "/audit", {
                "audit_id": "job-001", "capture": b64(frames)})
            self.assertEqual(status, 201)
            self.assertEqual(body["result"], "frozen")
            v = body["verdict"]
            self.assertEqual(v["verdict"], "closed_ok")
            self.assertEqual(v["frozen"]["file_length"], len(payload))
            self.assertEqual(v["frozen"]["coverage"],
                             [[0, len(payload)]])
            self.assertEqual(v["frozen"]["missing"], [])
            self.assertFalse(v["frozen"]["checksum_mismatch"])
            roles = {(m["role"], m["pdu"]) for m in v["phase_evidence"]}
            self.assertIn(("sender", "Metadata"), roles)
            self.assertIn(("sender", "EOF"), roles)
            # 无缺段闭环里没有 NAK
            self.assertNotIn(("receiver", "NAK"), roles)
            self.assertIn(("receiver", "Finished"), roles)

    def test_identical_capture_replays_frozen_verdict(self):
        frames, _ = closed_loop_frames(PAYLOAD)
        with ServerHarness() as h:
            s1, b1 = h.request("POST", "/audit",
                               {"audit_id": "dup", "capture": b64(frames)})
            self.assertEqual(s1, 201)
            s2, b2 = h.request("POST", "/audit",
                               {"audit_id": "dup", "capture": b64(frames)})
            self.assertEqual(s2, 200)
            self.assertEqual(b2["result"], "replayed")
            self.assertEqual(b2["verdict"], b1["verdict"])
            # GET 读取冻结裁决
            s3, b3 = h.request("GET", "/audit/dup")
            self.assertEqual(s3, 200)
            self.assertEqual(b3["verdict"], b1["verdict"])

    def test_changed_capture_conflicts(self):
        frames, _ = closed_loop_frames(PAYLOAD)
        changed = list(frames)
        # 翻转一帧方向位并重算 CRC
        import struct
        raw = bytearray(changed[1])
        raw[0] ^= 0x02
        raw[-4:] = struct.pack(">I", cfdp.crc32c(bytes(raw[:-4])))
        changed[1] = bytes(raw)

        with ServerHarness() as h:
            s1, _ = h.request("POST", "/audit",
                              {"audit_id": "c", "capture": b64(frames)})
            self.assertEqual(s1, 201)
            s2, b2 = h.request("POST", "/audit",
                               {"audit_id": "c", "capture": b64(changed)})
            self.assertEqual(s2, 409)
            self.assertEqual(b2["result"], "conflict")
            self.assertIn("original", b2)

    def test_missing_segment_reports_exact_nak_gap(self):
        frames, _ = closed_loop_frames(PAYLOAD[:64], with_loss=True,
                                       gap=(10, 18))
        # 截到 EOF（缺段未修复）
        cut = frames[:4]
        with ServerHarness() as h:
            s, b = h.request("POST", "/audit",
                             {"audit_id": "gap", "capture": b64(cut)})
            self.assertEqual(s, 201)
            v = b["verdict"]
            self.assertEqual(v["verdict"], "incomplete")
            self.assertEqual(v["frozen"]["missing"], [[10, 18]])
            self.assertEqual(v["frozen"]["first_missing_offset"], 10)

        # 完整修复序列应闭环
        with ServerHarness() as h:
            s, b = h.request("POST", "/audit",
                             {"audit_id": "gap-fixed",
                              "capture": b64(frames)})
            self.assertEqual(s, 201)
            self.assertEqual(b["verdict"]["verdict"], "closed_ok")

    def test_conflicting_retransmit_violation(self):
        frames, _ = closed_loop_frames(PAYLOAD[:32], with_conflict=True,
                                       gap=(4, 8))
        with ServerHarness() as h:
            s, b = h.request("POST", "/audit",
                             {"audit_id": "conflict",
                              "capture": b64(frames)})
            self.assertEqual(s, 201)
            fv = b["verdict"]["first_violation"]
            self.assertEqual(fv["reason"], "conflicting_retransmitted_data")
            self.assertEqual(fv["index"], 2)
            self.assertEqual(fv["phase"], "data_transfer")

    def test_bad_requests(self):
        with ServerHarness() as h:
            s, _ = h.request("POST", "/audit",
                             {"audit_id": "", "capture": ["AA=="]})
            self.assertEqual(s, 400)
            s, _ = h.request("POST", "/audit",
                             {"audit_id": "x", "capture": ["!!!"]})
            self.assertEqual(s, 400)
            s, _ = h.request("POST", "/audit",
                             {"audit_id": "x", "capture": []})
            self.assertEqual(s, 400)
            s, _ = h.request("GET", "/audit/missing")
            self.assertEqual(s, 404)


if __name__ == "__main__":
    unittest.main()
