"""补帧试算 HTTP 端到端测试。"""

import unittest

from app import cfdp
from tests.helpers import ENTITY, SEQ, closed_loop_frames
from tests.test_http import ServerHarness, PAYLOAD, b64


def incomplete_with_gap(gap=(10, 18), size=64):
    frames, payload = closed_loop_frames(PAYLOAD[:size], with_loss=True,
                                         gap=gap)
    return frames[:4], frames[4:], payload, gap


def post_repair(h, audit_id, repair_id, patch_b64):
    return h.request("POST", f"/audit/{audit_id}/repair", {
        "repair_id": repair_id, "supplement": patch_b64})


class TestRepairHTTP(unittest.TestCase):
    def test_successful_repair_closes_incomplete_source(self):
        cut, patch, payload, (s, e) = incomplete_with_gap()
        with ServerHarness() as h:
            sc, sb = h.request("POST", "/audit",
                               {"audit_id": "gap-ok-job", "capture": b64(cut)})
            self.assertEqual(sc, 201)
            self.assertEqual(sb["verdict"]["verdict"], "incomplete")

            status, body = post_repair(h, "gap-ok-job", "fix-ok-1", b64(patch))
            self.assertEqual(status, 201, body)
            self.assertEqual(body["result"], "frozen")
            r = body["repair"]

            self.assertTrue(r["eligible"])
            self.assertEqual(r["source_audit_id"], "gap-ok-job")
            self.assertEqual(r["source"]["verdict"], "incomplete")
            self.assertEqual(r["original_missing"], [[s, e]])
            self.assertEqual(r["supplement"]["covered"], [[s, e]])
            self.assertEqual(r["supplement"]["remaining_missing"], [])
            self.assertTrue(r["supplement"]["gaps_eliminated"])
            self.assertEqual(r["verdict"]["verdict"], "closed_ok")
            stages = [(m["pdu"], m["stage"])
                      for m in r["supplement"]["new_phase_evidence"]]
            self.assertEqual(stages, [
                ("NAK", "nak_for_uncovered"),
                ("FileData", "missing_data_retransmitted"),
                ("ACK", "ack_eof_complete"),
                ("Finished", "finished_complete"),
                ("ACK", "ack_finished_closed"),
            ])

            # 来源冻结结论保持不变
            _, g = h.request("GET", "/audit/gap-ok-job")
            self.assertEqual(g["verdict"]["verdict"], "incomplete")

    def test_identical_repair_input_replays_and_gets(self):
        cut, patch, _, _ = incomplete_with_gap()
        with ServerHarness() as h:
            h.request("POST", "/audit",
                      {"audit_id": "gap-rep-job", "capture": b64(cut)})
            s1, b1 = post_repair(h, "gap-rep-job", "fix-rep", b64(patch))
            self.assertEqual(s1, 201)
            s2, b2 = post_repair(h, "gap-rep-job", "fix-rep", b64(patch))
            self.assertEqual(s2, 200)
            self.assertEqual(b2["result"], "replayed")
            self.assertEqual(b2["repair"], b1["repair"])

            s3, b3 = h.request("GET", "/audit/gap-rep-job/repair/fix-rep")
            self.assertEqual(s3, 200)
            self.assertEqual(b3["repair"], b1["repair"])

    def test_changed_supplement_conflicts(self):
        cut, patch, _, _ = incomplete_with_gap()
        changed = list(patch)
        import struct
        raw = bytearray(patch[1])
        # 翻转补帧中重传 FileData 的一个载荷字节并重算 CRC
        raw[-5] ^= 0xFF
        raw[-4:] = struct.pack(">I", cfdp.crc32c(bytes(raw[:-4])))
        changed[1] = bytes(raw)
        with ServerHarness() as h:
            h.request("POST", "/audit",
                      {"audit_id": "gap-chg-job", "capture": b64(cut)})
            s1, _ = post_repair(h, "gap-chg-job", "fix-chg", b64(patch))
            self.assertEqual(s1, 201)
            s2, b2 = post_repair(h, "gap-chg-job", "fix-chg", b64(changed))
            self.assertEqual(s2, 409)
            self.assertEqual(b2["error"], "supplement_pdus_changed")
            self.assertIn("original", b2)

    def test_repair_id_bound_to_other_source_conflicts(self):
        cut, patch, _, _ = incomplete_with_gap()
        cut2, patch2, _, _ = incomplete_with_gap(gap=(20, 30))
        with ServerHarness() as h:
            h.request("POST", "/audit",
                      {"audit_id": "src-a", "capture": b64(cut)})
            h.request("POST", "/audit",
                      {"audit_id": "src-b", "capture": b64(cut2)})
            s1, _ = post_repair(h, "src-a", "fix", b64(patch))
            self.assertEqual(s1, 201)
            # 同一修复标识指向另一来源审计 → 冲突，回放首次结果
            s2, b2 = post_repair(h, "src-b", "fix", b64(patch2))
            self.assertEqual(s2, 409)
            self.assertEqual(b2["error"], "repair_source_changed")
            self.assertEqual(b2["original"]["source_audit_id"], "src-a")

    def test_non_incomplete_source_returns_trial_without_changing_source(self):
        frames, _ = closed_loop_frames(PAYLOAD[:64])
        tail = [cfdp.encode(cfdp.finished(ENTITY, SEQ))]
        with ServerHarness() as h:
            h.request("POST", "/audit",
                      {"audit_id": "closed-src-job", "capture": b64(frames)})
            status, body = post_repair(h, "closed-src-job", "fix-closed-src", b64(tail))
            self.assertEqual(status, 201)
            r = body["repair"]
            self.assertFalse(r["eligible"])
            self.assertEqual(r["ineligible_reason"],
                             "source_verdict_not_incomplete")
            self.assertEqual(r["verdict"]["verdict"], "violation")
            _, g = h.request("GET", "/audit/closed-src-job")
            self.assertEqual(g["verdict"]["verdict"], "closed_ok")

    def test_illegal_first_supplement_frozen_as_new_violation(self):
        cut, _, _, (s, e) = incomplete_with_gap()
        bad = [cfdp.encode(cfdp.ack_eof(ENTITY, SEQ))]
        with ServerHarness() as h:
            h.request("POST", "/audit",
                      {"audit_id": "gap-ill-job", "capture": b64(cut)})
            status, body = post_repair(h, "gap-ill-job", "fix-ill-bad", b64(bad))
            self.assertEqual(status, 201)
            r = body["repair"]
            self.assertEqual(r["verdict"]["verdict"], "violation")
            fv = r["verdict"]["first_violation"]
            self.assertEqual(fv["reason"], "premature_acknowledgement")
            self.assertEqual(fv["index"], 4)
            self.assertEqual(
                r["supplement"]["violation_relative_index"], 0)
            _, g = h.request("GET", "/audit/gap-ill-job")
            self.assertEqual(g["verdict"]["verdict"], "incomplete")

    def test_supplement_not_filling_gap_stays_incomplete(self):
        cut, _, _, (s, e) = incomplete_with_gap()
        only_nak = [cfdp.encode(cfdp.nak(ENTITY, SEQ, [(s, e)]))]
        with ServerHarness() as h:
            h.request("POST", "/audit",
                      {"audit_id": "gap-part-job", "capture": b64(cut)})
            status, body = post_repair(h, "gap-part-job", "fix-partial",
                                       b64(only_nak))
            self.assertEqual(status, 201)
            r = body["repair"]
            self.assertEqual(r["verdict"]["verdict"], "incomplete")
            self.assertFalse(r["supplement"]["gaps_eliminated"])
            self.assertEqual(r["supplement"]["remaining_missing"], [[s, e]])

    def test_errors(self):
        cut, patch, _, _ = incomplete_with_gap()
        with ServerHarness() as h:
            # 来源不存在
            s, b = post_repair(h, "missing", "fix", b64(patch))
            self.assertEqual(s, 404)
            self.assertEqual(b["error"], "audit_id_not_found")

            h.request("POST", "/audit",
                      {"audit_id": "gap-err-job", "capture": b64(cut)})
            # 缺 repair_id
            s, _ = h.request("POST", "/audit/gap-err-job/repair",
                             {"supplement": b64(patch)})
            self.assertEqual(s, 400)
            # 空/非法补帧
            s, b = h.request("POST", "/audit/gap-err-job/repair",
                             {"repair_id": "x", "supplement": []})
            self.assertEqual(s, 400)
            self.assertEqual(b["error"], "invalid_supplement")
            s, _ = h.request("POST", "/audit/gap-err-job/repair",
                             {"repair_id": "x", "supplement": ["!!!"]})
            self.assertEqual(s, 400)
            # 试算不存在
            s, _ = h.request("GET", "/audit/gap-err-job/repair/nope")
            self.assertEqual(s, 404)


if __name__ == "__main__":
    unittest.main()
