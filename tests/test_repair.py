"""缺段修复试算测试：补帧追加到已冻结 incomplete 捕获末尾重新裁决。"""

import base64
import unittest

from app import cfdp
from app import repair as repair_mod
from app.store import VerdictStore
from tests.helpers import ENTITY, SEQ
from tests.test_http import ServerHarness


PAYLOAD = bytes((i * 13 + 5) & 0xFF for i in range(64))
GAP = (10, 18)


def b64(frames):
    return [base64.b64encode(f).decode("ascii") for f in frames]


def incomplete_capture():
    """缺中段 GAP 的捕获，停在 EOF（等待 NAK/重传）。"""
    s, e = GAP
    return [
        cfdp.encode(cfdp.metadata(ENTITY, SEQ, len(PAYLOAD), "arc.dat")),
        cfdp.encode(cfdp.file_data(ENTITY, SEQ, 0, PAYLOAD[:s])),
        cfdp.encode(cfdp.file_data(ENTITY, SEQ, e, PAYLOAD[e:])),
        cfdp.encode(cfdp.eof(ENTITY, SEQ, len(PAYLOAD),
                             cfdp.crc32c(PAYLOAD))),
    ]


def repair_frames():
    """精确 NAK 缺口 → 重传补齐 → 闭环握手。"""
    s, e = GAP
    return [
        cfdp.encode(cfdp.nak(ENTITY, SEQ, [(s, e)])),
        cfdp.encode(cfdp.file_data(ENTITY, SEQ, s, PAYLOAD[s:e])),
        cfdp.encode(cfdp.ack_eof(ENTITY, SEQ)),
        cfdp.encode(cfdp.finished(ENTITY, SEQ)),
        cfdp.encode(cfdp.ack_finished(ENTITY, SEQ)),
    ]


def freeze_source(store, frames):
    from app import audit as audit_mod
    verdict = audit_mod.Auditor().run(frames).to_dict()
    entry, created, _ = store.submit("src", frames, verdict)
    assert created
    return entry


class TestSubtractRanges(unittest.TestCase):
    def test_difference(self):
        self.assertEqual(
            repair_mod.subtract_ranges([(0, 64)], [(0, 10), (18, 64)]),
            [(10, 18)])
        self.assertEqual(repair_mod.subtract_ranges([(0, 8)], [(0, 8)]), [])
        self.assertEqual(
            repair_mod.subtract_ranges([(0, 4), (8, 12)], [(2, 10)]),
            [(0, 2), (10, 12)])


class TestAdjudicate(unittest.TestCase):
    def setUp(self):
        self.store = VerdictStore()

    def test_success_fills_exactly_the_missing_gap(self):
        entry = freeze_source(self.store, incomplete_capture())
        r = repair_mod.adjudicate(entry, repair_frames())
        self.assertTrue(r["accepted"])
        self.assertIsNone(r["reject_reason"])
        self.assertEqual(r["source_verdict"], "incomplete")
        self.assertEqual(r["source_missing"], [[10, 18]])
        # 补帧新覆盖区间恰为原缺口：NAK 请求的字节确实被补回
        self.assertEqual(r["repair_coverage"], [[10, 18]])
        self.assertEqual(r["repair_pdu_count"], 5)
        self.assertEqual(r["combined_pdu_count"], 9)
        v = r["verdict"]
        self.assertEqual(v["verdict"], "closed_ok")
        self.assertEqual(v["frozen"]["missing"], [])
        stages = [m["stage"] for m in v["phase_evidence"]]
        self.assertEqual(stages, [
            "metadata_issued", "eof_sent", "nak_for_uncovered",
            "missing_data_retransmitted", "ack_eof_complete",
            "finished_complete", "ack_finished_closed",
        ])

    def test_source_not_incomplete(self):
        frames = incomplete_capture() + repair_frames()
        entry = freeze_source(self.store, frames)
        self.assertEqual(entry.verdict["verdict"], "closed_ok")
        r = repair_mod.adjudicate(entry, repair_frames())
        self.assertFalse(r["accepted"])
        self.assertEqual(r["reject_reason"],
                         repair_mod.RJ_SOURCE_NOT_INCOMPLETE)

    def test_gap_remaining(self):
        entry = freeze_source(self.store, incomplete_capture())
        # 只发 NAK 不重传：缺口仍在
        r = repair_mod.adjudicate(entry, repair_frames()[:1])
        self.assertFalse(r["accepted"])
        self.assertEqual(r["reject_reason"], repair_mod.RJ_GAP_REMAINING)
        self.assertEqual(r["verdict"]["verdict"], "incomplete")
        self.assertEqual(r["verdict"]["frozen"]["missing"], [[10, 18]])
        self.assertEqual(r["repair_coverage"], [])

    def test_first_frame_rejected(self):
        entry = freeze_source(self.store, incomplete_capture())
        # 跳过 NAK 直接重传：补帧首帧即违规
        r = repair_mod.adjudicate(entry, repair_frames()[1:])
        self.assertFalse(r["accepted"])
        self.assertEqual(r["reject_reason"],
                         repair_mod.RJ_FIRST_FRAME_REJECTED)
        fv = r["verdict"]["first_violation"]
        self.assertEqual(fv["reason"], "missing_nak_after_eof")
        self.assertEqual(fv["index"], len(incomplete_capture()))

    def test_protocol_violation_after_first_frame(self):
        entry = freeze_source(self.store, incomplete_capture())
        frames = repair_frames()
        # NAK 与重传合法，随后重传已覆盖字节且内容冲突
        bad = bytearray(PAYLOAD[:4])
        bad[0] ^= 0xFF
        frames = frames[:2] + [
            cfdp.encode(cfdp.file_data(ENTITY, SEQ, 0, bytes(bad)))]
        r = repair_mod.adjudicate(entry, frames)
        self.assertFalse(r["accepted"])
        self.assertEqual(r["reject_reason"],
                         repair_mod.RJ_PROTOCOL_VIOLATION)
        fv = r["verdict"]["first_violation"]
        self.assertEqual(fv["reason"], "conflicting_retransmitted_data")
        self.assertEqual(fv["index"], len(incomplete_capture()) + 2)


class TestRepairHTTP(unittest.TestCase):
    _seq = 0

    def _freeze_incomplete(self, h):
        # Handler.state 为类级共享（与既有 HTTP 测试一致），各用例用唯一标识
        type(self)._seq += 1
        audit_id = f"arc-{type(self)._seq}"
        s, b = h.request("POST", "/audit", {
            "audit_id": audit_id, "capture": b64(incomplete_capture())})
        self.assertEqual(s, 201)
        self.assertEqual(b["verdict"]["verdict"], "incomplete")
        self.assertEqual(b["verdict"]["frozen"]["missing"], [[10, 18]])
        return audit_id

    def test_repair_success_end_to_end(self):
        with ServerHarness() as h:
            arc = self._freeze_incomplete(h)
            s, b = h.request("POST", "/repair", {
                "repair_id": "fix-1", "audit_id": arc,
                "frames": b64(repair_frames())})
            self.assertEqual(s, 201)
            self.assertEqual(b["result"], "frozen")
            r = b["repair"]
            self.assertEqual(r["source_audit_id"], arc)
            self.assertEqual(r["source_verdict"], "incomplete")
            self.assertEqual(r["source_missing"], [[10, 18]])
            self.assertEqual(r["repair_coverage"], [[10, 18]])
            self.assertTrue(r["accepted"])
            self.assertIsNone(r["reject_reason"])
            self.assertEqual(r["verdict"]["verdict"], "closed_ok")
            stages = [m["stage"] for m in r["verdict"]["phase_evidence"]]
            self.assertIn("nak_for_uncovered", stages)
            self.assertIn("ack_finished_closed", stages)

            # 来源冻结结论不变
            s2, b2 = h.request("GET", f"/audit/{arc}")
            self.assertEqual(s2, 200)
            self.assertEqual(b2["verdict"]["verdict"], "incomplete")
            self.assertEqual(b2["verdict"]["frozen"]["missing"], [[10, 18]])

            # 修复裁决可读取
            s3, b3 = h.request("GET", "/repair/fix-1")
            self.assertEqual(s3, 200)
            self.assertEqual(b3["repair"], r)

    def test_repair_replay_and_conflict(self):
        with ServerHarness() as h:
            a1 = self._freeze_incomplete(h)
            a2 = self._freeze_incomplete(h)
            payload = {"repair_id": "fix", "audit_id": a1,
                       "frames": b64(repair_frames())}
            s1, b1 = h.request("POST", "/repair", payload)
            self.assertEqual(s1, 201)

            # 相同标识 + 完全相同输入 → 回放首次结果
            s2, b2 = h.request("POST", "/repair", payload)
            self.assertEqual(s2, 200)
            self.assertEqual(b2["result"], "replayed")
            self.assertEqual(b2["repair"], b1["repair"])

            # 替换来源 → 冲突
            s3, b3 = h.request("POST", "/repair", {
                "repair_id": "fix", "audit_id": a2,
                "frames": b64(repair_frames())})
            self.assertEqual(s3, 409)
            self.assertEqual(b3["result"], "conflict")
            self.assertEqual(b3["original"]["source_audit_id"], a1)

            # 任一原始补帧改变 → 冲突
            changed = repair_frames()
            changed[-1] = cfdp.encode(
                cfdp.ack_finished(ENTITY, SEQ, status=0))
            s4, b4 = h.request("POST", "/repair", {
                "repair_id": "fix", "audit_id": a1,
                "frames": b64(changed)})
            self.assertEqual(s4, 409)
            self.assertEqual(b4["result"], "conflict")

            # 冲突后原冻结修复裁决不变
            s5, b5 = h.request("GET", "/repair/fix")
            self.assertEqual(s5, 200)
            self.assertEqual(b5["repair"], b1["repair"])

    def test_repair_failures_return_new_verdict_source_untouched(self):
        with ServerHarness() as h:
            arc = self._freeze_incomplete(h)
            cases = []

            # 来源并非 incomplete
            s, b = h.request("POST", "/audit", {
                "audit_id": f"{arc}-ok",
                "capture": b64(incomplete_capture() + repair_frames())})
            self.assertEqual(b["verdict"]["verdict"], "closed_ok")
            s, b = h.request("POST", "/repair", {
                "repair_id": "rj-src", "audit_id": f"{arc}-ok",
                "frames": b64(repair_frames())})
            self.assertEqual(s, 201)
            self.assertFalse(b["repair"]["accepted"])
            self.assertEqual(b["repair"]["reject_reason"],
                             "source_not_incomplete")
            cases.append((f"{arc}-ok", "closed_ok"))

            # 补帧不能消除原缺口
            s, b = h.request("POST", "/repair", {
                "repair_id": "rj-gap", "audit_id": arc,
                "frames": b64(repair_frames()[:1])})
            self.assertEqual(s, 201)
            self.assertFalse(b["repair"]["accepted"])
            self.assertEqual(b["repair"]["reject_reason"], "gap_remaining")
            self.assertEqual(b["repair"]["verdict"]["verdict"], "incomplete")

            # 补帧首帧在当前阶段不合法
            s, b = h.request("POST", "/repair", {
                "repair_id": "rj-first", "audit_id": arc,
                "frames": b64(repair_frames()[1:])})
            self.assertEqual(s, 201)
            self.assertFalse(b["repair"]["accepted"])
            self.assertEqual(b["repair"]["reject_reason"],
                             "first_frame_rejected")
            self.assertEqual(b["repair"]["verdict"]["verdict"], "violation")

            # 仍产生协议违约
            bad = bytearray(PAYLOAD[:4])
            bad[0] ^= 0xFF
            frames = repair_frames()[:2] + [
                cfdp.encode(cfdp.file_data(ENTITY, SEQ, 0, bytes(bad)))]
            s, b = h.request("POST", "/repair", {
                "repair_id": "rj-vio", "audit_id": arc,
                "frames": b64(frames)})
            self.assertEqual(s, 201)
            self.assertFalse(b["repair"]["accepted"])
            self.assertEqual(b["repair"]["reject_reason"],
                             "protocol_violation")
            cases.append((arc, "incomplete"))

            # 所有失败均不改变来源冻结结论
            for audit_id, expect in cases:
                sg, bg = h.request("GET", f"/audit/{audit_id}")
                self.assertEqual(sg, 200)
                self.assertEqual(bg["verdict"]["verdict"], expect)

    def test_repair_bad_requests(self):
        with ServerHarness() as h:
            arc = self._freeze_incomplete(h)
            s, _ = h.request("POST", "/repair", {
                "repair_id": "", "audit_id": arc,
                "frames": b64(repair_frames())})
            self.assertEqual(s, 400)
            s, _ = h.request("POST", "/repair", {
                "repair_id": "r", "audit_id": "",
                "frames": b64(repair_frames())})
            self.assertEqual(s, 400)
            s, _ = h.request("POST", "/repair", {
                "repair_id": "r", "audit_id": arc, "frames": []})
            self.assertEqual(s, 400)
            s, _ = h.request("POST", "/repair", {
                "repair_id": "r", "audit_id": arc, "frames": ["!!!"]})
            self.assertEqual(s, 400)
            # 来源审计不存在
            s, b = h.request("POST", "/repair", {
                "repair_id": "r", "audit_id": "ghost",
                "frames": b64(repair_frames())})
            self.assertEqual(s, 404)
            self.assertEqual(b["error"], "audit_id_not_found")
            # 读取不存在的修复
            s, b = h.request("GET", "/repair/ghost")
            self.assertEqual(s, 404)
            self.assertEqual(b["error"], "repair_id_not_found")


if __name__ == "__main__":
    unittest.main()
