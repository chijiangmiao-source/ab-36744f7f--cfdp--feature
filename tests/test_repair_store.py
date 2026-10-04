"""补帧试算冻结存储测试。"""

import unittest

from app.store import VerdictStore


class TestRepairStore(unittest.TestCase):
    def setUp(self):
        self.store = VerdictStore()
        self.src_frames = [b"s1", b"s2"]
        self.patch = [b"p1", b"p2"]
        e, created, conflict = self.store.submit(
            "src", self.src_frames, {"verdict": "incomplete"})
        self.assertTrue(created)
        self.assertIsNone(conflict)
        self.source = e

    def test_freeze_replay_identical(self):
        e1, c1, cf1, _ = self.store.submit_repair(
            "fix", "src", self.source.cap_hash, self.patch,
            {"verdict": "closed_ok"}, 2)
        self.assertTrue(c1)
        self.assertIsNone(cf1)

        # 相同修复标识 + 完全相同输入 → 回放首次结果
        e2, c2, cf2, _ = self.store.submit_repair(
            "fix", "src", self.source.cap_hash, [b"p1", b"p2"],
            {"verdict": "SHOULD_NOT_REPLACE"}, 2)
        self.assertFalse(c2)
        self.assertIsNone(cf2)
        self.assertIs(e2, e1)
        self.assertEqual(e2.result["verdict"], "closed_ok")

    def test_change_supplement_is_conflict(self):
        self.store.submit_repair(
            "fix", "src", self.source.cap_hash, self.patch,
            {"verdict": "closed_ok"}, 2)
        # 任一原始补帧改变 / 顺序改变 / 增减帧均冲突
        for changed, reason in [
            ([b"p1", b"PX"], "supplement_pdus_changed"),
            ([b"p2", b"p1"], "supplement_pdus_changed"),
            ([b"p1"], "supplement_pdus_changed"),
            ([b"p1", b"p2", b"p3"], "supplement_pdus_changed"),
        ]:
            _, _, old, why = self.store.submit_repair(
                "fix", "src", self.source.cap_hash, changed,
                {"verdict": "x"}, 2)
            self.assertIsNotNone(old)
            self.assertEqual(why, reason, changed)

    def test_change_source_is_conflict(self):
        self.store.submit_repair(
            "fix", "src", self.source.cap_hash, self.patch,
            {"verdict": "closed_ok"}, 2)
        other, _, _ = self.store.submit(
            "other", [b"o1"], {"verdict": "incomplete"})
        _, _, old, why = self.store.submit_repair(
            "fix", "other", other.cap_hash, self.patch,
            {"verdict": "x"}, 1)
        self.assertIsNotNone(old)
        self.assertEqual(why, "repair_source_changed")

    def test_source_capture_hash_change_is_conflict(self):
        self.store.submit_repair(
            "fix", "src", self.source.cap_hash, self.patch,
            {"verdict": "closed_ok"}, 2)
        _, _, old, why = self.store.submit_repair(
            "fix", "src", b"deadbeef", self.patch,
            {"verdict": "x"}, 2)
        self.assertIsNotNone(old)
        self.assertEqual(why, "source_capture_changed")

    def test_distinct_repair_ids_independent(self):
        e1, n1, _, _ = self.store.submit_repair(
            "fix-a", "src", self.source.cap_hash, [b"a"],
            {"verdict": "incomplete"}, 2)
        e2, n2, _, _ = self.store.submit_repair(
            "fix-b", "src", self.source.cap_hash, [b"b"],
            {"verdict": "closed_ok"}, 2)
        self.assertTrue(n1 and n2)
        self.assertIsNot(e1, e2)
        self.assertIs(self.store.get_repair("fix-a"), e1)
        self.assertIsNone(self.store.get_repair("missing"))

    def test_source_frames_kept_frozen(self):
        # 来源条目保留原始帧字节，供试算严格追加引用
        self.assertEqual(self.source.frames, [b"s1", b"s2"])
        self.src_frames[0] = b"mutated-outside"
        self.assertEqual(self.source.frames, [b"s1", b"s2"])


if __name__ == "__main__":
    unittest.main()
