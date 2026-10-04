"""Class 2 闭环审计状态机测试。"""

import struct
import unittest

from app import cfdp
from app import audit as A
from tests.helpers import ENTITY, SEQ, closed_loop_frames


PAYLOAD = bytes((i * 37 + 11) & 0xFF for i in range(4096))


class TestClosedLoop(unittest.TestCase):
    def test_complete_loop(self):
        frames, payload = closed_loop_frames(PAYLOAD)
        v = A.Auditor().run(frames)
        self.assertEqual(v.verdict, "closed_ok")
        self.assertEqual(v.declared_length, len(payload))
        self.assertEqual(v.received_length, len(payload))
        self.assertEqual(v.coverage, [(0, len(payload))])
        self.assertEqual(v.missing, [])
        self.assertEqual(v.crc32c, f"{cfdp.crc32c(payload):08x}")
        self.assertFalse(v.checksum_mismatch)
        stages = [(m.role, m.pdu) for m in v.milestones]
        self.assertIn(("sender", "Metadata"), stages)
        self.assertIn(("sender", "EOF"), stages)
        self.assertIn(("receiver", "ACK"), stages)
        self.assertIn(("receiver", "Finished"), stages)
        # 双方阶段证据齐备且按闭环顺序
        order = [m.stage for m in v.milestones]
        self.assertEqual(order, [
            "metadata_issued", "eof_sent", "ack_eof_complete",
            "finished_complete", "ack_finished_closed",
        ])

    def test_overlapping_retransmit_consistent(self):
        # 重叠但字节一致：允许
        frames, payload = closed_loop_frames(PAYLOAD[:32])
        # 在 Metadata 后插入一段一致的重叠重传
        dup = cfdp.encode(cfdp.file_data(ENTITY, SEQ, 8, payload[8:24]))
        frames.insert(2, dup)
        v = A.Auditor().run(frames)
        self.assertEqual(v.verdict, "closed_ok")


class TestMissingSegmentRepair(unittest.TestCase):
    def test_missing_middle_then_nak_repair(self):
        frames, payload = closed_loop_frames(
            PAYLOAD[:64], with_loss=True, gap=(4, 8))
        # 截断到 NAK 之前：应报告不完整与精确缺口
        cut = frames[:4]  # metadata, data[0:4], data[8:64], eof
        v = A.Auditor().run(cut)
        self.assertEqual(v.verdict, "incomplete")
        self.assertEqual(v.phase, A.PH_EOF_RECOVERY)
        self.assertEqual(v.missing, [(4, 8)])
        self.assertEqual(v.first_missing_offset, 4)
        self.assertEqual(v.received_length, 60)

        # 完整修复序列：NAK 精确为 (4,8)
        v2 = A.Auditor().run(frames)
        self.assertEqual(v2.verdict, "closed_ok")
        self.assertEqual(v2.missing, [])
        nak_stages = [m for m in v2.milestones
                      if m.stage == "nak_for_uncovered"]
        self.assertEqual(len(nak_stages), 1)

    def test_nak_wrong_range_is_violation(self):
        frames, payload = closed_loop_frames(
            PAYLOAD[:64], with_loss=True, gap=(4, 8))
        # 把 NAK 替换为错误区间 (4,7)
        frames[4] = cfdp.encode(cfdp.nak(ENTITY, SEQ, [(4, 7)]))
        v = A.Auditor().run(frames)
        self.assertEqual(v.verdict, "violation")
        self.assertEqual(v.first_violation.reason, A.R_BAD_NAK_RANGE)
        self.assertEqual(v.first_violation.index, 4)
        self.assertEqual(v.first_violation.phase, A.PH_EOF_RECOVERY)
        self.assertEqual(v.first_violation.expected, [[4, 8]])
        self.assertEqual(v.first_violation.actual, [[4, 7]])

    def test_retransmit_before_nak_after_eof_is_violation(self):
        # EOF 后存在缺口却未发 NAK，直接重传补齐：违规
        payload = PAYLOAD[:32]
        frames = [
            cfdp.encode(cfdp.metadata(ENTITY, SEQ, 32)),
            cfdp.encode(cfdp.file_data(ENTITY, SEQ, 0, payload[0:8])),
            cfdp.encode(cfdp.file_data(ENTITY, SEQ, 12, payload[12:32])),
            cfdp.encode(cfdp.eof(ENTITY, SEQ, 32, cfdp.crc32c(payload))),
            cfdp.encode(cfdp.file_data(ENTITY, SEQ, 8, payload[8:12])),
        ]
        v = A.Auditor().run(frames)
        self.assertEqual(v.first_violation.reason, A.R_MISSING_NAK)
        self.assertEqual(v.first_violation.expected, [[8, 12]])

    def test_multiple_gaps_merged_nak(self):
        payload = PAYLOAD[:64]
        crc = cfdp.crc32c(payload)
        frames = [
            cfdp.encode(cfdp.metadata(ENTITY, SEQ, 64)),
            cfdp.encode(cfdp.file_data(ENTITY, SEQ, 0, payload[0:10])),
            cfdp.encode(cfdp.file_data(ENTITY, SEQ, 20, payload[20:40])),
            cfdp.encode(cfdp.file_data(ENTITY, SEQ, 50, payload[50:64])),
            cfdp.encode(cfdp.eof(ENTITY, SEQ, 64, crc)),
            cfdp.encode(cfdp.nak(ENTITY, SEQ,
                                 [(10, 20), (40, 50)])),
            cfdp.encode(cfdp.file_data(ENTITY, SEQ, 10, payload[10:20])),
            cfdp.encode(cfdp.file_data(ENTITY, SEQ, 40, payload[40:50])),
            cfdp.encode(cfdp.ack_eof(ENTITY, SEQ)),
            cfdp.encode(cfdp.finished(ENTITY, SEQ)),
            cfdp.encode(cfdp.ack_finished(ENTITY, SEQ)),
        ]
        v = A.Auditor().run(frames)
        self.assertEqual(v.verdict, "closed_ok")
        self.assertEqual(v.missing, [])

    def test_nak_coalesced_representation_equal(self):
        # 未覆盖为连续 (0,8) 时，NAK 以相邻 (0,4)+(4,8) 给出：
        # 规范化后覆盖集相等，予以接受（停在恢复阶段）。
        payload = PAYLOAD[:16]
        frames = [
            cfdp.encode(cfdp.metadata(ENTITY, SEQ, 16)),
            cfdp.encode(cfdp.file_data(ENTITY, SEQ, 8, payload[8:16])),
            cfdp.encode(cfdp.eof(ENTITY, SEQ, 16, cfdp.crc32c(payload))),
            cfdp.encode(cfdp.nak(ENTITY, SEQ, [(0, 4), (4, 8)])),
        ]
        v = A.Auditor().run(frames)
        self.assertIsNone(v.first_violation)
        self.assertEqual(v.verdict, "incomplete")
        self.assertEqual(v.phase, A.PH_EOF_RECOVERY)
        self.assertEqual(v.missing, [(0, 8)])

    def test_nak_partial_range_is_violation(self):
        # 只 NAK 缺口的一部分也不行
        payload = PAYLOAD[:16]
        frames = [
            cfdp.encode(cfdp.metadata(ENTITY, SEQ, 16)),
            cfdp.encode(cfdp.file_data(ENTITY, SEQ, 8, payload[8:16])),
            cfdp.encode(cfdp.eof(ENTITY, SEQ, 16, cfdp.crc32c(payload))),
            cfdp.encode(cfdp.nak(ENTITY, SEQ, [(0, 4)])),
        ]
        v = A.Auditor().run(frames)
        self.assertEqual(v.first_violation.reason, A.R_BAD_NAK_RANGE)
        self.assertEqual(v.first_violation.expected, [[0, 8]])
        self.assertEqual(v.first_violation.actual, [[0, 4]])


class TestViolations(unittest.TestCase):
    def _base(self, payload=PAYLOAD[:32]):
        frames, _ = closed_loop_frames(payload)
        return frames

    def test_conflicting_retransmit(self):
        frames, _ = closed_loop_frames(PAYLOAD[:32], with_conflict=True,
                                       gap=(4, 8))
        v = A.Auditor().run(frames)
        self.assertEqual(v.verdict, "violation")
        fv = v.first_violation
        self.assertEqual(fv.reason, A.R_RETRANSMIT_CONFLICT)
        self.assertEqual(fv.index, 2)
        self.assertIn("offset=4", fv.detail)
        self.assertEqual(fv.phase, A.PH_DATA_TRANSFER)

    def test_wrong_transaction_association(self):
        frames = self._base()
        frames[1] = cfdp.encode(
            cfdp.file_data(ENTITY + 1, SEQ, 0, PAYLOAD[:32]))
        v = A.Auditor().run(frames)
        self.assertEqual(v.first_violation.reason, A.R_TXN_ASSOCIATION)
        self.assertEqual(v.first_violation.index, 1)

    def test_premature_ack_with_missing_bytes(self):
        frames, payload = closed_loop_frames(
            PAYLOAD[:64], with_loss=True, gap=(4, 8))
        # 删除 NAK 与重传，EOF 后直接 ACK(EOF)
        frames = frames[:4] + [cfdp.encode(cfdp.ack_eof(ENTITY, SEQ))]
        v = A.Auditor().run(frames)
        self.assertEqual(v.first_violation.reason, A.R_PREMATURE_ACK)
        self.assertEqual(v.first_violation.expected, [[4, 8]])

    def test_wrong_ack_type(self):
        frames = self._base()
        # Finished 之后应 ACK(Finished)，替换成 ACK(EOF)
        idx = next(i for i, f in enumerate(frames)
                   if cfdp.decode(f).pdu_type == cfdp.T_ACK
                   and cfdp.decode(f).acked_type == cfdp.ACK_OF_FINISHED)
        frames[idx] = cfdp.encode(cfdp.ack_eof(ENTITY, SEQ))
        v = A.Auditor().run(frames)
        self.assertEqual(v.first_violation.reason, A.R_WRONG_ACK_TYPE)
        self.assertEqual(v.first_violation.phase, A.PH_FINISHED_SENT)

    def test_premature_finished_before_ack_eof(self):
        frames = self._base()
        # 删除 ACK(EOF)，Finished 提前到 EOF 之后
        frames = [f for f in frames
                  if not (cfdp.decode(f).pdu_type == cfdp.T_ACK
                          and cfdp.decode(f).acked_type == cfdp.ACK_OF_EOF)]
        v = A.Auditor().run(frames)
        self.assertEqual(v.first_violation.reason, A.R_PREMATURE_FINISHED)
        self.assertEqual(v.first_violation.phase, A.PH_EOF_RECOVERY)

    def test_write_after_terminal(self):
        frames = self._base()
        frames.append(cfdp.encode(
            cfdp.file_data(ENTITY, SEQ, 0, PAYLOAD[:32])))
        v = A.Auditor().run(frames)
        self.assertEqual(v.first_violation.reason, A.R_WRITE_AFTER_TERMINAL)
        self.assertTrue(v.reached_closed_before_violation)

    def test_crc_mismatch_blocks_ack(self):
        payload = PAYLOAD[:16]
        bad_crc = cfdp.crc32c(payload) ^ 0x12345678
        frames = [
            cfdp.encode(cfdp.metadata(ENTITY, SEQ, 16)),
            cfdp.encode(cfdp.file_data(ENTITY, SEQ, 0, payload)),
            cfdp.encode(cfdp.eof(ENTITY, SEQ, 16, bad_crc)),
            cfdp.encode(cfdp.ack_eof(ENTITY, SEQ)),
        ]
        v = A.Auditor().run(frames)
        self.assertEqual(v.first_violation.reason, A.R_CHECKSUM_MISMATCH)
        self.assertTrue(v.checksum_mismatch)

    def test_eof_size_mismatch(self):
        frames = [
            cfdp.encode(cfdp.metadata(ENTITY, SEQ, 16)),
            cfdp.encode(cfdp.file_data(ENTITY, SEQ, 0, PAYLOAD[:16])),
            cfdp.encode(cfdp.eof(ENTITY, SEQ, 17,
                                 cfdp.crc32c(PAYLOAD[:16]))),
        ]
        v = A.Auditor().run(frames)
        self.assertEqual(v.first_violation.reason, A.R_EOF_SIZE_MISMATCH)

    def test_nak_before_eof(self):
        frames = [
            cfdp.encode(cfdp.metadata(ENTITY, SEQ, 16)),
            cfdp.encode(cfdp.nak(ENTITY, SEQ, [(0, 16)])),
        ]
        v = A.Auditor().run(frames)
        self.assertEqual(v.first_violation.reason, A.R_PREMATURE_NAK)

    def test_data_beyond_size(self):
        frames = [
            cfdp.encode(cfdp.metadata(ENTITY, SEQ, 8)),
            cfdp.encode(cfdp.file_data(ENTITY, SEQ, 4, PAYLOAD[4:16])),
        ]
        v = A.Auditor().run(frames)
        self.assertEqual(v.first_violation.reason, A.R_DATA_OUT_OF_RANGE)

    def test_malformed_pdu_reports_index(self):
        frames = self._base()
        frames[2] = b"\xff\xff\x00\x01"  # 坏帧
        v = A.Auditor().run(frames)
        self.assertEqual(v.first_violation.reason, A.R_MALFORMED)
        self.assertEqual(v.first_violation.index, 2)

    def test_first_violation_phase_recorded(self):
        frames = [
            cfdp.encode(cfdp.file_data(ENTITY, SEQ, 0, PAYLOAD[:4])),
        ]
        v = A.Auditor().run(frames)
        self.assertEqual(v.first_violation.reason,
                         A.R_DATA_BEFORE_METADATA)
        self.assertEqual(v.first_violation.phase, A.PH_START)


if __name__ == "__main__":
    unittest.main()
