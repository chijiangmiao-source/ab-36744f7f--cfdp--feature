"""冻结裁决存储测试。"""

import unittest

from app.store import VerdictStore, decode_capture, capture_hash, CaptureError


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


if __name__ == "__main__":
    unittest.main()
