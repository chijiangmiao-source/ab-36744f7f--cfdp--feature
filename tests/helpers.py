"""测试辅助：构造各类事务捕获。"""

from __future__ import annotations

import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import cfdp
from app.cfdp import (
    STATUS_COMPLETE,
    STATUS_INCOMPLETE,
    T_ACK,
    T_EOF,
    T_FILE_DATA,
    T_FINISHED,
    T_METADATA,
    T_NAK,
    DIR_TO_RECEIVER,
    DIR_TO_SENDER,
)

ENTITY = 0x1001
SEQ = 0x0042


def encode64(pdu) -> str:
    return base64.b64encode(cfdp.encode(pdu)).decode("ascii")


def closed_loop_frames(payload: bytes, *, with_loss: bool = False,
                       with_conflict: bool = False,
                       gap=(4, 8)) -> tuple[list[bytes], bytes]:
    """返回完整闭环帧序列与文件载荷。

    with_loss=True 时先缺中段（gap），由 NAK 精确定位后重传补齐。
    with_conflict=True 时重传携带冲突字节。
    """
    src, seq = ENTITY, SEQ
    crc = cfdp.crc32c(payload)
    size = len(payload)
    frames: list[bytes] = []

    frames.append(cfdp.encode(cfdp.metadata(src, seq, size, "probe.dat")))
    if with_conflict:
        # 先发 [0,e)，再发 [s,size)，重叠区 [s,e) 首字节被改坏
        s, e = gap
        frames.append(cfdp.encode(cfdp.file_data(src, seq, 0, payload[:e])))
        bad = bytearray(payload[s:])
        bad[0] ^= 0xFF
        frames.append(cfdp.encode(cfdp.file_data(src, seq, s, bytes(bad))))
        return frames, payload

    if not with_loss:
        # 单段直发
        frames.append(cfdp.encode(cfdp.file_data(src, seq, 0, payload)))
    else:
        s, e = gap
        frames.append(cfdp.encode(cfdp.file_data(src, seq, 0, payload[:s])))
        frames.append(cfdp.encode(cfdp.file_data(src, seq, e, payload[e:])))
        frames.append(cfdp.encode(cfdp.eof(src, seq, size, crc)))
        # 接收方据未覆盖区间精确发 NAK
        frames.append(cfdp.encode(cfdp.nak(src, seq, [(s, e)])))
        if with_conflict:
            # 仅重传段首字节与原数据冲突
            bad = bytearray(payload[s:e])
            bad[0] ^= 0xFF
            frames.append(cfdp.encode(
                cfdp.file_data(src, seq, s, bytes(bad))))
        else:
            frames.append(cfdp.encode(
                cfdp.file_data(src, seq, s, payload[s:e])))
        frames.append(cfdp.encode(cfdp.ack_eof(src, seq, STATUS_COMPLETE)))
        frames.append(cfdp.encode(cfdp.finished(src, seq)))
        frames.append(cfdp.encode(cfdp.ack_finished(src, seq)))
        return frames, payload

    frames.append(cfdp.encode(cfdp.eof(src, seq, size, crc)))
    frames.append(cfdp.encode(cfdp.ack_eof(src, seq, STATUS_COMPLETE)))
    frames.append(cfdp.encode(cfdp.finished(src, seq)))
    frames.append(cfdp.encode(cfdp.ack_finished(src, seq)))
    return frames, payload


def audit(frames: list[bytes]):
    from app.audit import Auditor
    return Auditor().run(frames)


def flip_direction(raw: bytes) -> bytes:
    b = bytearray(raw)
    b[0] ^= 0x02  # direction bit
    # 重算 CRC
    import struct
    b[-4:] = struct.pack(">I", cfdp.crc32c(bytes(b[:-4])))
    return bytes(b)
