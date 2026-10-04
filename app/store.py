"""审计标识 → 冻结裁决存储。

同一审计标识：
  * 完全相同的捕获（Base64 序列逐字节一致，含方向位/顺序）→ 返回原冻结裁决；
  * 任一方向或原始 PDU 改变                            → 返回冲突。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import threading
from dataclasses import dataclass, field
from typing import Optional


class CaptureError(ValueError):
    """提交内容不是合法的 Base64 PDU 序列。"""


def decode_capture(items: list[str]) -> list[bytes]:
    if not isinstance(items, list) or not items:
        raise CaptureError("capture 必须是非空 Base64 字符串数组")
    frames: list[bytes] = []
    for n, item in enumerate(items):
        if not isinstance(item, str):
            raise CaptureError(f"capture[{n}] 不是字符串")
        try:
            frames.append(base64.b64decode(item, validate=True))
        except (binascii.Error, ValueError) as exc:
            raise CaptureError(f"capture[{n}] 不是合法 Base64: {exc}") from exc
    return frames


def capture_hash(frames: list[bytes]) -> str:
    h = hashlib.sha256()
    for frame in frames:
        h.update(len(frame).to_bytes(4, "big"))
        h.update(frame)
    return h.hexdigest()


@dataclass
class FrozenEntry:
    audit_id: str
    cap_hash: str
    verdict: dict
    pdu_count: int
    frames: list[bytes] = field(default_factory=list)


@dataclass
class RepairEntry:
    """补帧试算的冻结记录（与原审计标识空间分离，绝不改写来源结论）。"""
    repair_id: str
    source_audit_id: str
    source_cap_hash: str
    patch_hash: str
    result: dict
    source_pdu_count: int
    patch_pdu_count: int


class VerdictStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, FrozenEntry] = {}
        self._repairs: dict[str, RepairEntry] = {}

    def submit(self, audit_id: str, frames: list[bytes],
               verdict: dict) -> tuple[FrozenEntry, bool, Optional[FrozenEntry]]:
        """返回 (条目, 是否为本次新冻结, 冲突的旧条目)。

        相同标识 + 相同捕获 → (旧条目, False, None)
        相同标识 + 不同捕获 → (None, False, 旧条目)
        新标识              → (新条目, True, None)
        """
        cap = capture_hash(frames)
        with self._lock:
            old = self._entries.get(audit_id)
            if old is not None:
                if old.cap_hash == cap:
                    return old, False, None
                return old, False, old
            entry = FrozenEntry(audit_id, cap, verdict, len(frames),
                                list(frames))
            self._entries[audit_id] = entry
            return entry, True, None

    def get(self, audit_id: str) -> Optional[FrozenEntry]:
        with self._lock:
            return self._entries.get(audit_id)

    # ------------------------------------------------ 补帧试算

    def submit_repair(
        self, repair_id: str, source_audit_id: str, source_cap_hash: str,
        patch_frames: list[bytes], result: dict,
        source_pdu_count: int,
    ) -> tuple[RepairEntry, bool, Optional[RepairEntry], Optional[str]]:
        """冻结/回放/冲突一次补帧试算。

        指纹 = 来源审计标识 + 来源捕获指纹 + 补帧逐帧指纹：
          完全一致            → (旧条目, False, None, None) 回放
          换来源 / 来源捕获变 / 任一补帧变 → (..., 旧条目, 冲突原因)
          新修复标识          → (新条目, True, None, None)
        """
        patch_hash = capture_hash(patch_frames)
        with self._lock:
            old = self._repairs.get(repair_id)
            if old is not None:
                if (old.source_audit_id == source_audit_id
                        and old.source_cap_hash == source_cap_hash
                        and old.patch_hash == patch_hash):
                    return old, False, None, None
                if old.source_audit_id != source_audit_id:
                    why = "repair_source_changed"
                elif old.source_cap_hash != source_cap_hash:
                    why = "source_capture_changed"
                else:
                    why = "supplement_pdus_changed"
                return old, False, old, why
            entry = RepairEntry(repair_id, source_audit_id, source_cap_hash,
                                patch_hash, result, source_pdu_count,
                                len(patch_frames))
            self._repairs[repair_id] = entry
            return entry, True, None, None

    def get_repair(self, repair_id: str) -> Optional[RepairEntry]:
        with self._lock:
            return self._repairs.get(repair_id)
