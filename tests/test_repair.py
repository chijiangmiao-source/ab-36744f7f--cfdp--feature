"""补帧试算（在冻结 incomplete 捕获末尾严格追加补帧重新裁决）单元测试。"""

import unittest

from app import cfdp
from app import repair as repair_mod
from app.audit import Auditor
from app.store import VerdictStore
from tests.helpers import ENTITY, SEQ, closed_loop_frames


PAYLOAD = bytes((i * 37 + 11) & 0xFF for i in range(128))


def freeze_incomplete(gap=(10, 18), audit_id="gap"):
    """提交缺段、截到 EOF 的 incomplete 捕获，返回 (store, entry, payload, gap)。"""
    frames, payload = closed_loop_frames(PAYLOAD[:64], with_loss=True, gap=gap)
    cut = frames[:4]  # metadata, data[0:s), data[e:), eof
    verdict = Auditor().run(cut).to_dict()
    store = VerdictStore()
    entry, created, _ = store.submit(audit_id, cut, verdict)
    assert created
    return store, entry, payload, gap, cut, frames


def nak_for(gap):
    s, e = gap
    return [cfdp.encode(cfdp.nak(ENTITY, SEQ, [(s, e)]))]


class TestRepairSuccess(unittest.TestCase):
    def test_gap_closed_by_valid_supplement(self):
        store, entry, payload, (s, e), cut, _ = freeze_incomplete()
        patch = (
            nak_for((s, e))
            + [cfdp.encode(cfdp.file_data(ENTITY, SEQ, s, payload[s:e]))]
            + [cfdp.encode(cfdp.ack_eof(ENTITY, SEQ)),
               cfdp.encode(cfdp.finished(ENTITY, SEQ)),
               cfdp.encode(cfdp.ack_finished(ENTITY, SEQ))]
        )
        r = repair_mod.build_repair_result(entry, patch)

        # 成功结果须同时显示来源审计 / 原缺失 / 补帧覆盖 / 新闭环阶段证据
        self.assertTrue(r["eligible"])
        self.assertEqual(r["source"]["verdict"], "incomplete")
        self.assertEqual(r["source"]["audit_id"], "gap")
        self.assertEqual(r["original_missing"], [[s, e]])
        self.assertEqual(r["supplement"]["covered"], [[s, e]])
        self.assertEqual(r["supplement"]["remaining_missing"], [])
        self.assertTrue(r["supplement"]["gaps_eliminated"])
        self.assertEqual(r["verdict"]["verdict"], "closed_ok")
        self.assertEqual(r["verdict"]["frozen"]["coverage"],
                         [[0, len(payload)]])
        self.assertFalse(r["verdict"]["frozen"]["checksum_mismatch"])

        stages = [(m["pdu"], m["stage"])
                  for m in r["supplement"]["new_phase_evidence"]]
        self.assertEqual(stages, [
            ("NAK", "nak_for_uncovered"),
            ("FileData", "missing_data_retransmitted"),
            ("ACK", "ack_eof_complete"),
            ("Finished", "finished_complete"),
            ("ACK", "ack_finished_closed"),
        ])
        for m in r["supplement"]["new_phase_evidence"]:
            self.assertGreaterEqual(m["index"], 4)

        # 来源冻结结论保持 incomplete 且帧未被改写
        self.assertEqual(store.get("gap").verdict["verdict"], "incomplete")
        self.assertEqual(store.get("gap").pdu_count, 4)

    def test_overlapping_consistent_retransmit_counts_only_gap_bytes(self):
        store, entry, payload, (s, e), _, _ = freeze_incomplete()
        patch = (
            nak_for((s, e))
            # 与已收区域重叠但逐字节一致，同时覆盖缺口
            + [cfdp.encode(cfdp.file_data(ENTITY, SEQ, 0, payload[:e]))]
            + [cfdp.encode(cfdp.ack_eof(ENTITY, SEQ)),
               cfdp.encode(cfdp.finished(ENTITY, SEQ)),
               cfdp.encode(cfdp.ack_finished(ENTITY, SEQ))]
        )
        r = repair_mod.build_repair_result(entry, patch)
        self.assertEqual(r["verdict"]["verdict"], "closed_ok")
        # 补帧覆盖统计只含来源原本缺失的字节，不含重复确认的已收字节
        self.assertEqual(r["supplement"]["covered"], [[s, e]])


class TestRepairFailures(unittest.TestCase):
    def test_supplement_does_not_eliminate_gap(self):
        _, entry, payload, (s, e), _, _ = freeze_incomplete()
        # 仅发 NAK，不重传：缺口仍在
        r = repair_mod.build_repair_result(entry, nak_for((s, e)))
        self.assertEqual(r["verdict"]["verdict"], "incomplete")
        self.assertFalse(r["supplement"]["gaps_eliminated"])
        self.assertEqual(r["supplement"]["covered"], [])
        self.assertEqual(r["supplement"]["remaining_missing"], [[s, e]])

        # 重传只补一半：剩余缺口精确报告
        half = nak_for((s, e)) + [
            cfdp.encode(cfdp.file_data(ENTITY, SEQ, s, payload[s:s + 4]))]
        r2 = repair_mod.build_repair_result(entry, half)
        self.assertEqual(r2["verdict"]["verdict"], "incomplete")
        self.assertEqual(r2["supplement"]["covered"], [[s, s + 4]])
        self.assertEqual(r2["supplement"]["remaining_missing"],
                         [[s + 4, e]])

    def test_first_supplement_illegal_at_phase(self):
        # 来源处于 eof_recovery 且必须先 NAK，首帧直接 ACK(EOF) 不合法
        _, entry, _, (s, e), _, _ = freeze_incomplete()
        r = repair_mod.build_repair_result(
            entry, [cfdp.encode(cfdp.ack_eof(ENTITY, SEQ))])
        self.assertEqual(r["verdict"]["verdict"], "violation")
        fv = r["verdict"]["first_violation"]
        self.assertEqual(fv["reason"], "premature_acknowledgement")
        self.assertEqual(fv["phase"], "eof_recovery")
        # 违规定位在追加序列：全局 index=4，补帧内相对 index=0
        self.assertEqual(fv["index"], 4)
        self.assertTrue(r["supplement"]["first_violation_in_supplement"])
        self.assertEqual(r["supplement"]["violation_relative_index"], 0)

    def test_first_supplement_nak_wrong_range(self):
        _, entry, _, (s, e), _, _ = freeze_incomplete()
        r = repair_mod.build_repair_result(
            entry, [cfdp.encode(cfdp.nak(ENTITY, SEQ, [(s, e + 2)]))])
        self.assertEqual(r["verdict"]["verdict"], "violation")
        self.assertEqual(r["verdict"]["first_violation"]["reason"],
                         "nak_range_not_equal_uncovered")

    def test_protocol_violation_inside_supplement(self):
        _, entry, payload, (s, e), _, _ = freeze_incomplete()
        # 缺口补齐后用携带错误 CRC 语义的 ACK：正确补齐但 ACK 前先发坏字节
        # 这里构造重传字节与已收区冲突
        bad = bytearray(payload[8:e])
        bad[0] ^= 0xFF  # offset 8 已收，冲突
        patch = (nak_for((s, e))
                 + [cfdp.encode(cfdp.file_data(ENTITY, SEQ, 8, bytes(bad)))])
        r = repair_mod.build_repair_result(entry, patch)
        self.assertEqual(r["verdict"]["verdict"], "violation")
        fv = r["verdict"]["first_violation"]
        self.assertEqual(fv["reason"], "conflicting_retransmitted_data")
        self.assertEqual(r["supplement"]["violation_relative_index"], 1)

    def test_wrong_gap_bytes_then_ack_is_crc_violation(self):
        _, entry, payload, (s, e), _, _ = freeze_incomplete()
        wrong = bytearray(payload[s:e])
        wrong[0] ^= 0xFF
        patch = (nak_for((s, e))
                 + [cfdp.encode(cfdp.file_data(ENTITY, SEQ, s, bytes(wrong))),
                    cfdp.encode(cfdp.ack_eof(ENTITY, SEQ))])
        r = repair_mod.build_repair_result(entry, patch)
        self.assertEqual(r["verdict"]["verdict"], "violation")
        self.assertEqual(r["verdict"]["first_violation"]["reason"],
                         "crc32c_mismatch")
        # 表面全覆盖（缺口区间已填），但 CRC 不符，不能闭环
        self.assertEqual(r["supplement"]["covered"], [[s, e]])
        self.assertEqual(r["supplement"]["remaining_missing"], [])
        self.assertTrue(r["supplement"]["gaps_eliminated"])


class TestRepairEligibility(unittest.TestCase):
    def _source(self, verdict_name, frames):
        verdict = Auditor().run(frames).to_dict()
        self.assertEqual(verdict["verdict"], verdict_name)
        store = VerdictStore()
        entry, _, _ = store.submit("src", frames, verdict)
        return store, entry

    def test_closed_source_ineligible_but_verdict_still_computed(self):
        frames, payload = closed_loop_frames(PAYLOAD[:64])
        store, entry = self._source("closed_ok", frames)
        # 闭环后再补任何帧：新裁决违规，但来源结论不变
        r = repair_mod.build_repair_result(
            entry, [cfdp.encode(cfdp.finished(ENTITY, SEQ))])
        self.assertFalse(r["eligible"])
        self.assertEqual(r["ineligible_reason"],
                         "source_verdict_not_incomplete")
        self.assertEqual(r["verdict"]["verdict"], "violation")
        self.assertTrue(
            r["verdict"]["reached_closed_before_violation"])
        self.assertEqual(store.get("src").verdict["verdict"], "closed_ok")

    def test_violation_source_ineligible(self):
        frames, _ = closed_loop_frames(PAYLOAD[:32], with_conflict=True,
                                       gap=(4, 8))
        store, entry = self._source("violation", frames)
        # 来源已有首个违规，追加帧不能改变该违规裁决
        r = repair_mod.build_repair_result(
            entry, [cfdp.encode(cfdp.nak(ENTITY, SEQ, [(0, 4)]))])
        self.assertFalse(r["eligible"])
        self.assertEqual(r["verdict"]["verdict"], "violation")
        self.assertFalse(
            r["supplement"]["first_violation_in_supplement"])
        self.assertEqual(store.get("src").verdict["verdict"], "violation")


if __name__ == "__main__":
    unittest.main()
