"""CFDP Class 2 事务闭环审计状态机。

按捕获顺序喂入同一事务双向 PDU，产出冻结裁决：
  closed_ok  — 完整覆盖、CRC32C 相符、Finished 握手闭环、双方阶段证据齐备
  incomplete — 捕获在闭环前终止（附未覆盖区间/首个缺口/当前阶段）
  violation  — 捕获内出现首个违规 PDU（附其序号、当时阶段、原因、期望/实际）

审查规则要点：
  1. 所有 PDU 必须属于同一 (源实体, 事务号)；
  2. 方向位必须与 PDU 类型匹配（Metadata/FileData/EOF 向下行，ACK/NAK/Finished 向上行）；
  3. 事务必须以 Metadata 起始，EOF 尺寸须与 Metadata 一致；
  4. FileData 可重传，但与已收字节重叠处必须逐字节一致；
  5. EOF 后若存在未覆盖区间，接收方必须先按未覆盖区间（合并后精确相等）发 NAK；
  6. 补齐覆盖且 CRC32C 校验相符后，才允许 ACK(EOF,complete)；
  7. 随后 Finished(complete,noerror) → ACK(Finished,complete) 闭环；
  8. 终态（收到 ACK(Finished)）后再写入/出现任何 PDU 均违规。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import cfdp
from .cfdp import (
    ACK_OF_EOF,
    ACK_OF_FINISHED,
    COND_NOERROR,
    DIR_TO_RECEIVER,
    DIR_TO_SENDER,
    STATUS_COMPLETE,
    T_ACK,
    T_EOF,
    T_FILE_DATA,
    T_FINISHED,
    T_METADATA,
    T_NAK,
    PDU,
)

# ---------------------------------------------------------------- 阶段

PH_START = "start"
PH_DATA_TRANSFER = "data_transfer"
PH_EOF_RECOVERY = "eof_recovery"
PH_EOF_ACKED = "eof_acked"
PH_FINISHED_SENT = "finished_sent"
PH_CLOSED = "closed"

NEXT_PHASE = {
    PH_START: "等待 Metadata",
    PH_DATA_TRANSFER: "数据传输（EOF 前）",
    PH_EOF_RECOVERY: "EOF 后丢段恢复（NAK/重传）",
    PH_EOF_ACKED: "已 ACK(EOF)，等待 Finished",
    PH_FINISHED_SENT: "已 Finished，等待 ACK(Finished)",
    PH_CLOSED: "事务已闭环",
}

# ---------------------------------------------------------------- 违规原因

R_MALFORMED = "malformed_pdu"
R_TXN_ASSOCIATION = "wrong_transaction_association"
R_DIRECTION = "direction_type_mismatch"
R_NO_METADATA = "metadata_not_first"
R_DUPLICATE_METADATA = "duplicate_metadata"
R_DATA_BEFORE_METADATA = "data_before_metadata"
R_DATA_OUT_OF_RANGE = "data_beyond_declared_size"
R_RETRANSMIT_CONFLICT = "conflicting_retransmitted_data"
R_DUPLICATE_EOF = "duplicate_eof"
R_EOF_SIZE_MISMATCH = "eof_size_mismatch"
R_PREMATURE_NAK = "nak_before_eof"
R_MISSING_NAK = "missing_nak_after_eof"
R_BAD_NAK_RANGE = "nak_range_not_equal_uncovered"
R_SPURIOUS_NAK = "nak_without_uncovered_range"
R_LATE_NAK = "nak_after_verification"
R_PREMATURE_ACK = "premature_acknowledgement"
R_WRONG_ACK_TYPE = "wrong_ack_type"
R_BAD_ACK_STATUS = "bad_ack_status"
R_PREMATURE_FINISHED = "premature_finished"
R_DUPLICATE_FINISHED = "duplicate_finished"
R_CHECKSUM_MISMATCH = "crc32c_mismatch"
R_WRITE_AFTER_TERMINAL = "write_after_terminal"
R_PDU_AFTER_CLOSED = "pdu_after_closed"

DOWNSTREAM_TYPES = {T_METADATA, T_FILE_DATA, T_EOF}
UPSTREAM_TYPES = {T_ACK, T_NAK, T_FINISHED}


@dataclass
class Violation:
    index: int
    pdu_type: str
    direction: str
    phase: str
    reason: str
    detail: str
    expected: Optional[object] = None
    actual: Optional[object] = None


@dataclass
class Milestone:
    index: int
    role: str
    pdu: str
    stage: str


@dataclass
class Verdict:
    verdict: str
    src_entity: Optional[int] = None
    seq: Optional[int] = None
    file_name: Optional[str] = None
    declared_length: Optional[int] = None
    received_length: int = 0
    crc32c: Optional[str] = None
    checksum_mismatch: bool = False
    coverage: list[tuple[int, int]] = field(default_factory=list)
    missing: list[tuple[int, int]] = field(default_factory=list)
    first_missing_offset: Optional[int] = None
    phase: str = PH_START
    milestones: list[Milestone] = field(default_factory=list)
    first_violation: Optional[Violation] = None
    pdu_count: int = 0
    reached_closed_before_violation: bool = False

    def to_dict(self) -> dict:
        def iv(ivs: list[tuple[int, int]]) -> list[list[int]]:
            return [[s, e] for s, e in ivs]

        d = {
            "verdict": self.verdict,
            "transaction": {
                "src_entity": self.src_entity,
                "seq": self.seq,
                "file_name": self.file_name,
                "declared_length": self.declared_length,
            },
            "frozen": {
                "file_length": self.declared_length,
                "received_length": self.received_length,
                "crc32c": self.crc32c,
                "checksum_mismatch": self.checksum_mismatch,
                "coverage": iv(self.coverage),
                "missing": iv(self.missing),
                "first_missing_offset": self.first_missing_offset,
            },
            "phase": self.phase,
            "phase_hint": NEXT_PHASE.get(self.phase, self.phase),
            "phase_evidence": [vars(m) for m in self.milestones],
            "first_violation": vars(self.first_violation)
            if self.first_violation
            else None,
            "pdu_count": self.pdu_count,
            "reached_closed_before_violation":
                self.reached_closed_before_violation,
        }
        return d


def merge_runs(mask: bytearray) -> list[tuple[int, int]]:
    """把布尔掩码合并为 [start, end) 区间。"""
    out: list[tuple[int, int]] = []
    start = None
    for i, v in enumerate(mask):
        if v and start is None:
            start = i
        elif not v and start is not None:
            out.append((start, i))
            start = None
    if start is not None:
        out.append((start, len(mask)))
    return out


def invert(runs: list[tuple[int, int]], size: int) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    cur = 0
    for s, e in runs:
        if s > cur:
            out.append((cur, s))
        cur = max(cur, e)
    if cur < size:
        out.append((cur, size))
    return out


def normalize_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for s, e in sorted(ranges):
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


class Auditor:
    def __init__(self) -> None:
        self.phase = PH_START
        self.v = Verdict(verdict="incomplete")
        self._key: Optional[tuple[int, int]] = None
        self._size: Optional[int] = None
        self._buf = bytearray()
        self._mask = bytearray()
        self._eof_crc: Optional[int] = None
        self._full_checked_crc: Optional[int] = None
        # EOF 后若存在未覆盖区间，必须先收到与之精确相等的 NAK 才允许重传补齐
        self._awaiting_nak = False

    # ------------------------------------------------ 公共入口

    def run(self, frames: list[bytes]) -> Verdict:
        self.v.pdu_count = len(frames)
        for i, raw in enumerate(frames):
            try:
                pdu = cfdp.decode(raw)
            except cfdp.PDUError as exc:
                self._fail(i, None, R_MALFORMED, str(exc))
                return self.v
            if self._step(i, pdu):
                return self.v
        self._finish()
        return self.v

    # ------------------------------------------------ 内部

    def _fail(self, index: int, pdu: Optional[PDU], reason: str,
              detail: str, expected: object = None,
              actual: object = None) -> bool:
        if self.phase == PH_CLOSED:
            self.v.reached_closed_before_violation = True
        self.v.first_violation = Violation(
            index=index,
            pdu_type=pdu.type_name if pdu is not None else "Undecodable",
            direction=("to_sender" if pdu and pdu.direction == DIR_TO_SENDER
                       else "to_receiver" if pdu else "unknown"),
            phase=self.phase,
            reason=reason,
            detail=detail,
            expected=expected,
            actual=actual,
        )
        self.v.verdict = "violation"
        self._snapshot()
        return True

    def _milestone(self, i: int, pdu: PDU, stage: str) -> None:
        role = "sender" if pdu.direction == DIR_TO_RECEIVER else "receiver"
        self.v.milestones.append(Milestone(i, role, pdu.type_name, stage))

    def _uncovered(self) -> list[tuple[int, int]]:
        if self._size is None:
            return []
        return invert(merge_runs(self._mask), self._size)

    def _snapshot(self) -> None:
        if self._size is not None:
            covered = merge_runs(self._mask)
            missing = invert(covered, self._size)
            self.v.coverage = covered
            self.v.missing = missing
            self.v.first_missing_offset = missing[0][0] if missing else None
            self.v.received_length = sum(e - s for s, e in covered)
            if not missing:
                self._full_checked_crc = cfdp.crc32c(bytes(self._buf))
                self.v.crc32c = f"{self._full_checked_crc:08x}"
                if (self._eof_crc is not None
                        and self._full_checked_crc != self._eof_crc):
                    self.v.checksum_mismatch = True
        self.v.phase = self.phase
        self.v.src_entity = self._key[0] if self._key else None
        self.v.seq = self._key[1] if self._key else None
        self.v.declared_length = self._size

    def _crc_ok(self) -> Optional[bool]:
        """全覆盖时返回 CRC 是否相符；否则 None。"""
        if self._size is None or self._uncovered():
            return None
        calc = cfdp.crc32c(bytes(self._buf))
        return calc == (self._eof_crc or 0)

    def _step(self, i: int, pdu: PDU) -> bool:
        v = self.v
        # 事务关联
        if self._key is None:
            self._key = pdu.transaction_key()
        elif pdu.transaction_key() != self._key:
            return self._fail(
                i, pdu, R_TXN_ASSOCIATION,
                f"PDU 属于事务 (entity={pdu.src_entity},seq={pdu.seq})，"
                f"与当前事务 (entity={self._key[0]},seq={self._key[1]}) 不符",
                expected=[self._key[0], self._key[1]],
                actual=[pdu.src_entity, pdu.seq],
            )

        # 方向与类型匹配
        if pdu.direction == DIR_TO_RECEIVER:
            if pdu.pdu_type not in DOWNSTREAM_TYPES:
                return self._fail(i, pdu, R_DIRECTION,
                                  "接收方向 PDU 携带了上行类型，方向位错误")
        else:
            if pdu.pdu_type not in UPSTREAM_TYPES:
                return self._fail(i, pdu, R_DIRECTION,
                                  "发送方向 PDU 携带了下行类型，方向位错误")

        t = pdu.pdu_type

        # ------------------------------------------------ Metadata
        if t == T_METADATA:
            if self.phase != PH_START:
                return self._fail(i, pdu, R_DUPLICATE_METADATA,
                                  "Metadata 必须且只能作为首个 PDU 出现一次")
            self._size = pdu.file_size
            v.file_name = pdu.file_name
            self._buf = bytearray(self._size)
            self._mask = bytearray(self._size)
            self._awaiting_nak = False
            self.phase = PH_DATA_TRANSFER
            self._milestone(i, pdu, "metadata_issued")
            self._snapshot()
            return False

        # 任何非 Metadata 出现在起点
        if self.phase == PH_START:
            return self._fail(i, pdu, R_DATA_BEFORE_METADATA,
                              "事务必须以 Metadata 起始")

        # ------------------------------------------------ FileData
        if t == T_FILE_DATA:
            if self.phase == PH_CLOSED:
                return self._fail(
                    i, pdu, R_WRITE_AFTER_TERMINAL,
                    f"终态闭环后仍写入 FileData offset={pdu.offset} "
                    f"length={len(pdu.segment)}，旧成功结论撤销",
                )
            if self.phase == PH_EOF_RECOVERY and self._awaiting_nak:
                missing = self._uncovered()
                return self._fail(
                    i, pdu, R_MISSING_NAK,
                    "EOF 后存在未覆盖区间，必须先由未覆盖区间生成 NAK，"
                    "禁止在 NAK 前直接重传补齐",
                    expected=[list(r) for r in missing],
                )
            assert self._size is not None
            off, seg = pdu.offset, pdu.segment
            if off + len(seg) > self._size:
                return self._fail(
                    i, pdu, R_DATA_OUT_OF_RANGE,
                    f"FileData [{off},{off + len(seg)}) 越过声明长度 "
                    f"{self._size}",
                    expected=self._size, actual=off + len(seg),
                )
            for k, byte in enumerate(seg):
                pos = off + k
                if self._mask[pos]:
                    if self._buf[pos] != byte:
                        return self._fail(
                            i, pdu, R_RETRANSMIT_CONFLICT,
                            f"offset={pos} 重传字节冲突：原字节 "
                            f"0x{self._buf[pos]:02x}，新字节 0x{byte:02x}",
                            expected=f"0x{self._buf[pos]:02x}",
                            actual=f"0x{byte:02x}",
                        )
                else:
                    self._buf[pos] = byte
                    self._mask[pos] = 1
            if self.phase == PH_EOF_RECOVERY:
                self._milestone(i, pdu, "missing_data_retransmitted")
            self._snapshot()
            return False

        # ------------------------------------------------ EOF
        if t == T_EOF:
            if self.phase != PH_DATA_TRANSFER:
                return self._fail(i, pdu, R_DUPLICATE_EOF,
                                  "EOF 只能出现一次且须在数据传输阶段末尾")
            if pdu.file_size != self._size:
                return self._fail(
                    i, pdu, R_EOF_SIZE_MISMATCH,
                    f"EOF 声明长度 {pdu.file_size} 与 Metadata 声明 "
                    f"{self._size} 不符",
                    expected=self._size, actual=pdu.file_size,
                )
            self._eof_crc = pdu.file_crc32c
            self.phase = PH_EOF_RECOVERY
            self._awaiting_nak = bool(self._uncovered())
            self._milestone(i, pdu, "eof_sent")
            self._snapshot()
            return False

        # ------------------------------------------------ NAK
        if t == T_NAK:
            if self.phase in (PH_DATA_TRANSFER,):
                return self._fail(i, pdu, R_PREMATURE_NAK,
                                  "EOF 到达前不允许 NAK")
            if self.phase in (PH_EOF_ACKED, PH_FINISHED_SENT, PH_CLOSED):
                return self._fail(i, pdu, R_LATE_NAK,
                                  "覆盖与校验已通过，不允许再发 NAK")
            missing = self._uncovered()
            got = normalize_ranges(pdu.nak_ranges or [])
            if not missing:
                return self._fail(i, pdu, R_SPURIOUS_NAK,
                                  "已无未覆盖区间，该 NAK 为多余 NAK",
                                  expected=[], actual=[list(r) for r in got])
            if got != missing:
                return self._fail(
                    i, pdu, R_BAD_NAK_RANGE,
                    "NAK 区间必须与当前未覆盖区间（合并后）精确相等",
                    expected=[list(r) for r in missing],
                    actual=[list(r) for r in got],
                )
            self._awaiting_nak = False
            self._milestone(i, pdu, "nak_for_uncovered")
            self._snapshot()
            return False

        # ------------------------------------------------ ACK
        if t == T_ACK:
            if pdu.acked_type == ACK_OF_EOF:
                if self.phase == PH_EOF_RECOVERY:
                    missing = self._uncovered()
                    if missing:
                        return self._fail(
                            i, pdu, R_PREMATURE_ACK,
                            f"仍有 {len(missing)} 个未覆盖区间，"
                            "未补齐即 ACK(EOF) 属于过早确认",
                            expected=[list(r) for r in missing],
                            actual=[pdu.acked_type, pdu.acked_status],
                        )
                    if self._crc_ok() is False:
                        return self._fail(
                            i, pdu, R_CHECKSUM_MISMATCH,
                            f"全覆盖但 CRC32C 不符：EOF 携带 "
                            f"{self._eof_crc:08x}，实算 "
                            f"{cfdp.crc32c(bytes(self._buf)):08x}",
                            expected=f"{self._eof_crc:08x}",
                            actual=f"{cfdp.crc32c(bytes(self._buf)):08x}",
                        )
                    if pdu.acked_status != STATUS_COMPLETE:
                        return self._fail(
                            i, pdu, R_BAD_ACK_STATUS,
                            "ACK(EOF) 状态必须为 complete(1)",
                            expected=STATUS_COMPLETE, actual=pdu.acked_status,
                        )
                    self.phase = PH_EOF_ACKED
                    self._milestone(i, pdu, "ack_eof_complete")
                    self._snapshot()
                    return False
                if self.phase in (PH_FINISHED_SENT, PH_CLOSED):
                    return self._fail(
                        i, pdu, R_WRONG_ACK_TYPE,
                        "当前阶段需要 ACK(Finished)，却收到 ACK(EOF)",
                        expected=ACK_OF_FINISHED, actual=ACK_OF_EOF,
                    )
                return self._fail(i, pdu, R_PREMATURE_ACK,
                                  "EOF 到达前不允许 ACK(EOF)")

            if pdu.acked_type == ACK_OF_FINISHED:
                if self.phase == PH_FINISHED_SENT:
                    if pdu.acked_status != STATUS_COMPLETE:
                        return self._fail(
                            i, pdu, R_BAD_ACK_STATUS,
                            "ACK(Finished) 状态必须为 complete(1)",
                            expected=STATUS_COMPLETE, actual=pdu.acked_status,
                        )
                    self.phase = PH_CLOSED
                    self._milestone(i, pdu, "ack_finished_closed")
                    self._snapshot()
                    return False
                if self.phase == PH_EOF_ACKED:
                    return self._fail(i, pdu, R_PREMATURE_ACK,
                                      "Finished 尚未发出，不能先 ACK(Finished)")
                if self.phase == PH_CLOSED:
                    return self._fail(i, pdu, R_PDU_AFTER_CLOSED,
                                      "闭环后重复 ACK(Finished)")
                return self._fail(
                    i, pdu, R_WRONG_ACK_TYPE,
                    "当前阶段不接受 ACK(Finished)（应先 NAK 补齐 / ACK(EOF)）",
                )

        # ------------------------------------------------ Finished
        if t == T_FINISHED:
            if self.phase == PH_EOF_ACKED:
                if (pdu.condition_code != COND_NOERROR
                        or pdu.finish_status != STATUS_COMPLETE):
                    return self._fail(
                        i, pdu, R_PREMATURE_FINISHED,
                        "Finished 必须为 complete/noerror 才能成功闭环",
                        expected=[COND_NOERROR, STATUS_COMPLETE],
                        actual=[pdu.condition_code, pdu.finish_status],
                    )
                self.phase = PH_FINISHED_SENT
                self._milestone(i, pdu, "finished_complete")
                self._snapshot()
                return False
            if self.phase == PH_EOF_RECOVERY:
                missing = self._uncovered()
                why = ("仍有未覆盖区间" if missing
                       else "尚未经过 ACK(EOF)")
                return self._fail(
                    i, pdu, R_PREMATURE_FINISHED,
                    f"{why}，禁止在补齐校验前进入 Finished 握手",
                    expected=[list(r) for r in missing] if missing else
                    "先 ACK(EOF)",
                )
            if self.phase == PH_FINISHED_SENT:
                return self._fail(i, pdu, R_DUPLICATE_FINISHED,
                                  "Finished 重复发送")
            if self.phase == PH_CLOSED:
                return self._fail(i, pdu, R_PDU_AFTER_CLOSED,
                                  "闭环后重复 Finished")
            return self._fail(i, pdu, R_PREMATURE_FINISHED,
                              "EOF 前不允许 Finished")

        return self._fail(i, pdu, R_MALFORMED, f"未处理的 PDU 类型 {t}")

    # ------------------------------------------------ 收尾

    def _finish(self) -> None:
        self._snapshot()
        if self.phase == PH_CLOSED:
            self.v.verdict = "closed_ok"
            return
        self.v.verdict = "incomplete"
