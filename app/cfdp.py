"""短头 / 16 位实体与事务号的 CFDP PDU 编解码（仅本审计器支持的子集）。

支持的 PDU（acknowledged mode, Class 2）：
  Metadata / File Data / EOF / ACK / NAK / Finished

固定头 8 字节：
  byte0  version(3)=001 | pdu_type(3) | direction(1) | CRC flag(1)
  byte1  类型相关标志
  2-3    源实体 ID (u16, big endian)
  4-5    事务序号 (u16, big endian)
  6-7    PDU data field 长度 (u16, big endian)
  尾部   4 字节 CRC32C（CRC flag=1 时覆盖头+data field）

文件上限 64 KiB；文件长度/FileData 偏移/NAK 边界为 u32（足以表达到
65536），实体 ID 与事务号保持 u16。多字节整数一律大端。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

MAX_FILE_SIZE = 64 * 1024

VERSION = 0b001
DIR_TO_RECEIVER = 0
DIR_TO_SENDER = 1

# PDU 类型（3 bit）
T_METADATA = 0
T_FILE_DATA = 1
T_EOF = 2
T_ACK = 3
T_NAK = 4
T_FINISHED = 5
PDU_TYPE_NAMES = {
    T_METADATA: "Metadata",
    T_FILE_DATA: "FileData",
    T_EOF: "EOF",
    T_ACK: "ACK",
    T_NAK: "NAK",
    T_FINISHED: "Finished",
}

# ACK 被确认的 PDU 类型
ACK_OF_EOF = 2
ACK_OF_FINISHED = 5

# ACK / Finished 状态码
STATUS_INCOMPLETE = 0
STATUS_COMPLETE = 1

# Finished 条件码
COND_NOERROR = 0


class PDUError(ValueError):
    """PDU 结构非法。"""


@dataclass
class PDU:
    pdu_type: int
    src_entity: int
    seq: int
    direction: int = DIR_TO_RECEIVER
    crc_flag: bool = True
    # type-specific
    file_size: Optional[int] = None          # Metadata / EOF
    file_name: Optional[str] = None          # Metadata
    segment: Optional[bytes] = None          # FileData
    offset: Optional[int] = None             # FileData
    file_crc32c: Optional[int] = None        # EOF
    acked_type: Optional[int] = None         # ACK
    acked_status: Optional[int] = None       # ACK
    finish_status: Optional[int] = None      # ACK(Finished) / Finished
    condition_code: Optional[int] = None     # Finished
    nak_ranges: Optional[list[tuple[int, int]]] = None  # NAK [(start,end))
    raw: bytes = b""

    @property
    def type_name(self) -> str:
        return PDU_TYPE_NAMES.get(self.pdu_type, f"Unknown({self.pdu_type})")

    def transaction_key(self) -> tuple[int, int]:
        return (self.src_entity, self.seq)


# ---------------------------------------------------------------- CRC32C

def crc32c(data: bytes) -> int:
    """Castagnoli CRC-32（多项式 0x82F63B41 反射形式，初值/异或出 0xFFFFFFFF）。"""
    table = getattr(crc32c, "_table", None)
    if table is None:
        table = []
        for n in range(256):
            c = n
            for _ in range(8):
                c = (c >> 1) ^ 0x82F63B78 if (c & 1) else c >> 1
            table.append(c)
        crc32c._table = table  # type: ignore[attr-defined]
    crc = 0xFFFFFFFF
    for byte in data:
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


# ---------------------------------------------------------------- 编码

def _u16(v: int) -> bytes:
    if not (0 <= v <= 0xFFFF):
        raise PDUError(f"u16 越界: {v}")
    return struct.pack(">H", v)


def _u32(v: int) -> bytes:
    if not (0 <= v <= 0xFFFFFFFF):
        raise PDUError(f"u32 越界: {v}")
    return struct.pack(">I", v)


def _assemble(pdu_type: int, type_flags: int, pdu: PDU,
              body: bytes, direction: int) -> bytes:
    b0 = ((VERSION & 0x07) << 5) | ((pdu_type & 0x07) << 2) \
        | ((direction & 1) << 1) | (1 if pdu.crc_flag else 0)
    hdr = bytes([b0, type_flags & 0xFF]) + _u16(pdu.src_entity) \
        + _u16(pdu.seq) + _u16(len(body))
    out = hdr + body
    if pdu.crc_flag:
        out += struct.pack(">I", crc32c(out))
    return out


def encode(pdu: PDU) -> bytes:
    """编码 PDU，CRC flag=1 时追加 4 字节 CRC32C。"""
    body = b""

    if pdu.pdu_type == T_METADATA:
        name = (pdu.file_name or "").encode("utf-8")
        if len(name) > 0xFF:
            raise PDUError("文件名过长")
        size = pdu.file_size if pdu.file_size is not None else 0
        if size > MAX_FILE_SIZE:
            raise PDUError("文件超过 64KiB")
        body = _u32(size) + bytes([len(name)]) + name
        return _assemble(T_METADATA, 0, pdu, body, DIR_TO_RECEIVER)

    if pdu.pdu_type == T_FILE_DATA:
        if pdu.segment is None or pdu.offset is None:
            raise PDUError("FileData 缺少 offset/segment")
        if pdu.offset > MAX_FILE_SIZE or pdu.offset + len(pdu.segment) > MAX_FILE_SIZE:
            raise PDUError("FileData 覆盖越过 64KiB")
        body = _u32(pdu.offset) + bytes(pdu.segment)
        return _assemble(T_FILE_DATA, 0, pdu, body, DIR_TO_RECEIVER)

    if pdu.pdu_type == T_EOF:
        if pdu.file_size is None or pdu.file_crc32c is None:
            raise PDUError("EOF 缺少 file_size/crc")
        body = _u32(pdu.file_size) + struct.pack(">I", pdu.file_crc32c)
        return _assemble(T_EOF, 0, pdu, body, DIR_TO_RECEIVER)

    if pdu.pdu_type == T_ACK:
        if pdu.acked_type is None or pdu.acked_status is None:
            raise PDUError("ACK 缺少被确认类型/状态")
        fs = pdu.finish_status if pdu.finish_status is not None else 0
        body = bytes([pdu.acked_type, pdu.acked_status, fs])
        return _assemble(T_ACK, 0, pdu, body, DIR_TO_SENDER)

    if pdu.pdu_type == T_NAK:
        ranges = pdu.nak_ranges or []
        if not ranges:
            raise PDUError("NAK 至少包含一个区间")
        for start, end in ranges:
            if not (0 <= start < end <= MAX_FILE_SIZE):
                raise PDUError(f"NAK 区间非法: ({start},{end})")
            body += _u32(start) + _u32(end)
        return _assemble(T_NAK, 0, pdu, body, DIR_TO_SENDER)

    if pdu.pdu_type == T_FINISHED:
        cond = pdu.condition_code if pdu.condition_code is not None else COND_NOERROR
        fs = pdu.finish_status if pdu.finish_status is not None else STATUS_COMPLETE
        # type_flags: condition(4) | delivery(1) | status(1) | reserved(2)
        delivery = 1 if cond == COND_NOERROR else 0
        type_flags = (cond << 4) | (delivery << 3) | ((fs & 1) << 2)
        return _assemble(T_FINISHED, type_flags, pdu, b"", DIR_TO_SENDER)

    raise PDUError(f"不支持的 PDU 类型: {pdu.pdu_type}")


def encode_with_crc_override(pdu: PDU, crc_value: int) -> bytes:
    """编码并把尾部 CRC 替换为指定值（构造坏 CRC 样本用）。"""
    pdu.crc_flag = True
    raw = encode(pdu)
    return raw[:-4] + struct.pack(">I", crc_value)


# ---------------------------------------------------------------- 解码

def decode(raw: bytes) -> PDU:
    if len(raw) < 8:
        raise PDUError(f"短头不足 8 字节（实际 {len(raw)}）")
    b0, b1 = raw[0], raw[1]
    version = (b0 >> 5) & 0x07
    pdu_type = (b0 >> 2) & 0x07
    direction = (b0 >> 1) & 0x01
    crc_flag = bool(b0 & 0x01)
    type_flags = b1
    src, seq, dlen = struct.unpack(">HHH", raw[2:8])

    if version != VERSION:
        raise PDUError(f"不支持的版本: {version}")
    if pdu_type > T_FINISHED:
        raise PDUError(f"不支持的 PDU 类型: {pdu_type}")

    expected_total = 8 + dlen + (4 if crc_flag else 0)
    if len(raw) != expected_total:
        raise PDUError(
            f"{PDU_TYPE_NAMES.get(pdu_type, pdu_type)} 长度不符: "
            f"头声明 data={dlen} crc={'有' if crc_flag else '无'}，"
            f"应 {expected_total} 字节，实际 {len(raw)}"
        )
    data = raw[8:8 + dlen]
    if crc_flag:
        (stored,) = struct.unpack(">I", raw[8 + dlen:8 + dlen + 4])
        if crc32c(raw[:8 + dlen]) != stored:
            raise PDUError(f"{PDU_TYPE_NAMES[pdu_type]} CRC32C 校验失败")

    pdu = PDU(pdu_type=pdu_type, src_entity=src, seq=seq,
              direction=direction, crc_flag=crc_flag, raw=bytes(raw))

    if pdu_type == T_METADATA:
        if len(data) < 5:
            raise PDUError("Metadata data field 过短")
        (size,) = struct.unpack(">I", data[0:4])
        nlen = data[4]
        if len(data) < 5 + nlen:
            raise PDUError("Metadata 文件名截断")
        if nlen and len(data) != 5 + nlen:
            raise PDUError("Metadata 尾部多余字节")
        if size > MAX_FILE_SIZE:
            raise PDUError("Metadata 声明文件超过 64KiB")
        pdu.file_size = size
        pdu.file_name = data[5:5 + nlen].decode("utf-8", errors="replace")

    elif pdu_type == T_FILE_DATA:
        if len(data) < 4:
            raise PDUError("FileData data field 过短")
        (off,) = struct.unpack(">I", data[0:4])
        seg = data[4:]
        if off + len(seg) > MAX_FILE_SIZE:
            raise PDUError("FileData 覆盖越过 64KiB")
        pdu.offset = off
        pdu.segment = seg

    elif pdu_type == T_EOF:
        if len(data) != 8:
            raise PDUError("EOF data field 应为 8 字节")
        (size,) = struct.unpack(">I", data[0:4])
        (crc,) = struct.unpack(">I", data[4:8])
        if size > MAX_FILE_SIZE:
            raise PDUError("EOF 声明文件超过 64KiB")
        pdu.file_size = size
        pdu.file_crc32c = crc

    elif pdu_type == T_ACK:
        if len(data) != 3:
            raise PDUError("ACK data field 应为 3 字节")
        at, st, fs = data[0], data[1], data[2]
        if at not in (ACK_OF_EOF, ACK_OF_FINISHED):
            raise PDUError(f"ACK 被确认类型非法: {at}")
        pdu.acked_type = at
        pdu.acked_status = st
        pdu.finish_status = fs

    elif pdu_type == T_NAK:
        if len(data) < 8 or len(data) % 8 != 0:
            raise PDUError("NAK data field 应为 8 的倍数且非空")
        ranges = []
        for i in range(0, len(data), 8):
            start, end = struct.unpack(">II", data[i:i + 8])
            if start >= end:
                raise PDUError(f"NAK 空/倒序区间: ({start},{end})")
            if end > MAX_FILE_SIZE:
                raise PDUError("NAK 区间越过 64KiB")
            ranges.append((start, end))
        pdu.nak_ranges = ranges

    elif pdu_type == T_FINISHED:
        pdu.condition_code = (type_flags >> 4) & 0x0F
        pdu.finish_status = (type_flags >> 2) & 0x01

    return pdu


# ---------------------------------------------------------------- 便捷构造

def metadata(src: int, seq: int, size: int, name: str = "") -> PDU:
    return PDU(T_METADATA, src, seq, file_size=size, file_name=name)


def file_data(src: int, seq: int, offset: int, data: bytes) -> PDU:
    return PDU(T_FILE_DATA, src, seq, offset=offset, segment=bytes(data))


def eof(src: int, seq: int, size: int, file_crc: int) -> PDU:
    return PDU(T_EOF, src, seq, file_size=size, file_crc32c=file_crc)


def ack_eof(src: int, seq: int, status: int = STATUS_COMPLETE) -> PDU:
    return PDU(T_ACK, src, seq, direction=DIR_TO_SENDER,
               acked_type=ACK_OF_EOF, acked_status=status)


def ack_finished(src: int, seq: int, status: int = STATUS_COMPLETE) -> PDU:
    return PDU(T_ACK, src, seq, direction=DIR_TO_SENDER,
               acked_type=ACK_OF_FINISHED, acked_status=status)


def nak(src: int, seq: int, ranges: list[tuple[int, int]]) -> PDU:
    return PDU(T_NAK, src, seq, direction=DIR_TO_SENDER, nak_ranges=ranges)


def finished(src: int, seq: int, status: int = STATUS_COMPLETE,
             condition: int = COND_NOERROR) -> PDU:
    return PDU(T_FINISHED, src, seq, direction=DIR_TO_SENDER,
               finish_status=status, condition_code=condition)
