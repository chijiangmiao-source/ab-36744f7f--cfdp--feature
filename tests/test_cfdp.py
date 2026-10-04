"""PDU 编解码与 CRC32C 测试。"""

import struct
import unittest

from app import cfdp
from app.cfdp import (
    ACK_OF_EOF,
    ACK_OF_FINISHED,
    DIR_TO_RECEIVER,
    DIR_TO_SENDER,
    MAX_FILE_SIZE,
    STATUS_COMPLETE,
    T_ACK,
    T_EOF,
    T_FILE_DATA,
    T_FINISHED,
    T_METADATA,
    T_NAK,
)
from tests.helpers import ENTITY, SEQ


class TestCRC32C(unittest.TestCase):
    def test_known_vectors(self):
        # Castagnoli 标准向量
        self.assertEqual(cfdp.crc32c(b""), 0x00000000)
        self.assertEqual(cfdp.crc32c(b"123456789"), 0xE3069283)

    def test_deterministic(self):
        data = bytes(range(256))
        self.assertEqual(cfdp.crc32c(data), cfdp.crc32c(data))


class TestRoundTrip(unittest.TestCase):
    def test_metadata(self):
        raw = cfdp.encode(cfdp.metadata(ENTITY, SEQ, 1234, "a/b.dat"))
        pdu = cfdp.decode(raw)
        self.assertEqual(pdu.pdu_type, T_METADATA)
        self.assertEqual(pdu.src_entity, ENTITY)
        self.assertEqual(pdu.seq, SEQ)
        self.assertEqual(pdu.file_size, 1234)
        self.assertEqual(pdu.file_name, "a/b.dat")
        self.assertEqual(pdu.direction, DIR_TO_RECEIVER)
        # 头8 + size(u32)4 + nlen1 + name7 + crc4
        self.assertEqual(len(raw), 8 + 4 + 1 + 7 + 4)

    def test_file_data(self):
        seg = bytes(range(250))
        raw = cfdp.encode(cfdp.file_data(ENTITY, SEQ, 1000, seg))
        pdu = cfdp.decode(raw)
        self.assertEqual(pdu.pdu_type, T_FILE_DATA)
        self.assertEqual(pdu.offset, 1000)
        self.assertEqual(pdu.segment, seg)

    def test_eof(self):
        raw = cfdp.encode(cfdp.eof(ENTITY, SEQ, 64, 0xDEADBEEF))
        pdu = cfdp.decode(raw)
        self.assertEqual(pdu.pdu_type, T_EOF)
        self.assertEqual(pdu.file_size, 64)
        self.assertEqual(pdu.file_crc32c, 0xDEADBEEF)

    def test_ack_eof_and_finished(self):
        for factory, at in ((cfdp.ack_eof, ACK_OF_EOF),
                            (cfdp.ack_finished, ACK_OF_FINISHED)):
            pdu = cfdp.decode(cfdp.encode(factory(ENTITY, SEQ)))
            self.assertEqual(pdu.pdu_type, T_ACK)
            self.assertEqual(pdu.direction, DIR_TO_SENDER)
            self.assertEqual(pdu.acked_type, at)
            self.assertEqual(pdu.acked_status, STATUS_COMPLETE)

    def test_nak(self):
        raw = cfdp.encode(cfdp.nak(ENTITY, SEQ, [(0, 10), (20, 64)]))
        pdu = cfdp.decode(raw)
        self.assertEqual(pdu.pdu_type, T_NAK)
        self.assertEqual(pdu.nak_ranges, [(0, 10), (20, 64)])

    def test_finished(self):
        raw = cfdp.encode(cfdp.finished(ENTITY, SEQ))
        pdu = cfdp.decode(raw)
        self.assertEqual(pdu.pdu_type, T_FINISHED)
        self.assertEqual(pdu.direction, DIR_TO_SENDER)
        self.assertEqual(pdu.condition_code, 0)
        self.assertEqual(pdu.finish_status, STATUS_COMPLETE)

    def test_max_size_boundary(self):
        # 64KiB 文件由分段承载；验证末段恰好落在边界
        seg = b"y" * 1024
        off = MAX_FILE_SIZE - len(seg)
        raw = cfdp.encode(cfdp.file_data(ENTITY, SEQ, off, seg))
        self.assertEqual(cfdp.decode(raw).segment, seg)
        # 越过边界 1 字节即非法
        with self.assertRaises(cfdp.PDUError):
            cfdp.encode(cfdp.file_data(ENTITY, SEQ, off + 1, seg))
        # 单段 data field 不能超过 u16（但不影响 64KiB 文件分段传输）
        with self.assertRaises(cfdp.PDUError):
            cfdp.encode(cfdp.file_data(
                ENTITY, SEQ, 0, b"x" * (MAX_FILE_SIZE + 1)))


class TestMalformed(unittest.TestCase):
    def test_truncated_header(self):
        with self.assertRaises(cfdp.PDUError):
            cfdp.decode(b"\x20\x00\x10")

    def test_bad_version(self):
        raw = bytearray(cfdp.encode(cfdp.metadata(ENTITY, SEQ, 0)))
        raw[0] |= 0xE0  # version = 111
        with self.assertRaises(cfdp.PDUError):
            cfdp.decode(bytes(raw))

    def test_bad_crc_rejected(self):
        raw = cfdp.encode_with_crc_override(
            cfdp.metadata(ENTITY, SEQ, 10), 0x00000000)
        with self.assertRaises(cfdp.PDUError):
            cfdp.decode(raw)

    def test_length_field_mismatch(self):
        raw = bytearray(cfdp.encode(cfdp.nak(ENTITY, SEQ, [(0, 4)])))
        raw[6] = 0x00
        raw[7] = 0x09  # 声明 9 字节，实际 8
        with self.assertRaises(cfdp.PDUError):
            cfdp.decode(bytes(raw))

    def test_nak_empty_range_rejected(self):
        with self.assertRaises(cfdp.PDUError):
            cfdp.encode(cfdp.nak(ENTITY, SEQ, [(5, 5)]))

    def test_ack_unknown_type(self):
        body = bytes([9, 1, 0])
        b0 = (cfdp.VERSION << 5) | (T_ACK << 2) | (DIR_TO_SENDER << 1) | 1
        hdr = bytes([b0, 0]) + struct.pack(">HHH", ENTITY, SEQ, len(body))
        raw = hdr + body
        raw += struct.pack(">I", cfdp.crc32c(raw))
        with self.assertRaises(cfdp.PDUError):
            cfdp.decode(raw)


if __name__ == "__main__":
    unittest.main()
