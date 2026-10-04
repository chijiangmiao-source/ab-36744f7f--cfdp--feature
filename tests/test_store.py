"""冻结裁决存储测试。"""

import unittest

from app.store import (
    CaptureError,
    RepairStore,
    VerdictStore,
    capture_hash,
    decode_capture,
)


class TestDecodeCapture(unittest.TestCase):
    def test_ok(self):
        import base64
        frames = decode_capture([base64.b64encode(b"abc").decode(),
                                 base64.b64encode(b"").decode()])
        self.assertEqual(frames, [b"abc", b""])

    def test_empty_rejected(self):
        with self.assertRaises(CaptureError):
            decode_capture([])

    def test_bad_base64(self):
        with self.assertRaises(CaptureError):
            decode_capture(["!!!not-b64!!!"])


class TestVerdictStore(unittest.TestCase):
    def setUp(self):
        self.store = VerdictStore()

    def test_freeze_replay_conflict(self):
        frames = [b"\x00\x01", b"\x02\x03"]
        entry, created, conflict = self.store.submit(
            "A", frames, {"verdict": "closed_ok"})
        self.assertTrue(created)
        self.assertIsNone(conflict)

        # 完全相同捕获 → 原冻结裁决
        e2, created2, c2 = self.store.submit(
            "A", [b"\x00\x01", b"\x02\x03"], {"verdict": "OTHER"})
        self.assertFalse(created2)
        self.assertIsNone(c2)
        self.assertIs(e2, entry)
        self.assertEqual(e2.verdict["verdict"], "closed_ok")

    def test_direction_or_pdu_change_is_conflict(self):
        # 顺序改变即冲突
        _, _, c = self.store.submit("A", [b"a", b"b"], {"verdict": "x"})
        self.assertIsNone(c)
        _, _, c2 = self.store.submit("A", [b"b", b"a"], {"verdict": "x"})
        self.assertIsNotNone(c2)
        # 任一原始 PDU 改变即冲突
        _, _, c3 = self.store.submit("A", [b"a", b"B"], {"verdict": "x"})
        self.assertIsNotNone(c3)
        # 增加一帧也算改变
        _, _, c4 = self.store.submit("A", [b"a", b"b", b"c"], {"verdict": "x"})
        self.assertIsNotNone(c4)

    def test_distinct_audit_ids_independent(self):
        e1, n1, _ = self.store.submit("A", [b"x"], {"verdict": "1"})
        e2, n2, _ = self.store.submit("B", [b"x"], {"verdict": "2"})
        self.assertTrue(n1 and n2)
        self.assertIsNot(e1, e2)
        self.assertEqual(self.store.get("A").verdict["verdict"], "1")

    def test_hash_sensitive(self):
        self.assertNotEqual(capture_hash([b"a", b"b"]),
                            capture_hash([b"b", b"a"]))

    def test_frozen_entry_keeps_original_capture(self):
        frames = [b"\x00\x01", b"\x02\x03"]
        entry, created, _ = self.store.submit("A", frames, {"verdict": "x"})
        self.assertTrue(created)
        # 冻结的原始捕获可被修复试算引用
        self.assertEqual(entry.frames, frames)


class TestRepairStore(unittest.TestCase):
    def setUp(self):
        self.store = RepairStore()

    def test_freeze_replay_conflict(self):
        frames = [b"\x0a", b"\x0b"]
        entry, created, conflict = self.store.submit(
            "R", "src", frames, {"accepted": True})
        self.assertTrue(created)
        self.assertIsNone(conflict)

        # 相同标识 + 相同来源与补帧 → 回放首次冻结结果
        e2, created2, c2 = self.store.submit(
            "R", "src", [b"\x0a", b"\x0b"], {"accepted": False})
        self.assertFalse(created2)
        self.assertIsNone(c2)
        self.assertIs(e2, entry)
        self.assertTrue(e2.repair["accepted"])

    def test_replace_source_is_conflict(self):
        self.store.submit("R", "src", [b"a"], {"accepted": True})
        _, created, conflict = self.store.submit(
            "R", "other", [b"a"], {"accepted": True})
        self.assertFalse(created)
        self.assertIsNotNone(conflict)
        self.assertEqual(conflict.audit_id, "src")

    def test_any_repair_frame_change_is_conflict(self):
        self.store.submit("R", "src", [b"a", b"b"], {"accepted": True})
        # 顺序改变
        _, _, c1 = self.store.submit("R", "src", [b"b", b"a"], {})
        self.assertIsNotNone(c1)
        # 任一原始补帧改变
        _, _, c2 = self.store.submit("R", "src", [b"a", b"B"], {})
        self.assertIsNotNone(c2)
        # 增删补帧
        _, _, c3 = self.store.submit("R", "src", [b"a"], {})
        self.assertIsNotNone(c3)

    def test_distinct_repair_ids_independent(self):
        e1, n1, _ = self.store.submit("R1", "src", [b"x"], {"accepted": 1})
        e2, n2, _ = self.store.submit("R2", "src", [b"x"], {"accepted": 2})
        self.assertTrue(n1 and n2)
        self.assertIsNot(e1, e2)
        self.assertEqual(self.store.get("R1").repair["accepted"], 1)
        self.assertIsNone(self.store.get("R3"))


if __name__ == "__main__":
    unittest.main()
