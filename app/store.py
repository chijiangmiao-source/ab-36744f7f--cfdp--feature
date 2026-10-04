"""审计标识 → 冻结裁决存储；修复标识 → 冻结修复裁决存储。

同一审计标识：
  * 完全相同的捕获（Base64 序列逐字节一致，含方向位/顺序）→ 返回原冻结裁决；
  * 任一方向或原始 PDU 改变                            → 返回冲突。

同一修复标识：
  * 来源审计标识与补帧序列完全一致 → 回放首次冻结的修复裁决；
  * 替换来源或任一原始补帧改变     → 返回冲突。
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


def decode_capture(items: list[str], field: str = "capture") -> list[bytes]:
    if not isinstance(items, list) or not items:
        raise CaptureError(f"{field} 必须是非空 Base64 字符串数组")
    frames: list[bytes] = []
    for n, item in enumerate(items):
        if not isinstance(item, str):
            raise CaptureError(f"{field}[{n}] 不是字符串")
        try:
            frames.append(base64.b64decode(item, validate=True))
        except (binascii.Error, ValueError) as exc:
            raise CaptureError(f"{field}[{n}] 不是合法 Base64: {exc}") from exc
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
    # 冻结的原始捕获（修复试算只能引用它，不得改写）
    frames: list[bytes] = field(default_factory=list)


class VerdictStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, FrozenEntry] = {}

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


@dataclass
class RepairEntry:
    repair_id: str
    audit_id: str
    cap_hash: str
    repair: dict
    pdu_count: int


class RepairStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, RepairEntry] = {}

    def submit(self, repair_id: str, audit_id: str, frames: list[bytes],
               repair: dict) -> tuple[RepairEntry, bool, Optional[RepairEntry]]:
        """返回 (条目, 是否为本次新冻结, 冲突的旧条目)。

        相同标识 + 相同来源与补帧 → (旧条目, False, None)
        相同标识 + 来源或补帧改变 → (None, False, 旧条目)
        新标识                    → (新条目, True, None)
        """
        cap = capture_hash(frames)
        with self._lock:
            old = self._entries.get(repair_id)
            if old is not None:
                if old.audit_id == audit_id and old.cap_hash == cap:
                    return old, False, None
                return old, False, old
            entry = RepairEntry(repair_id, audit_id, cap, repair, len(frames))
            self._entries[repair_id] = entry
            return entry, True, None

    def get(self, repair_id: str) -> Optional[RepairEntry]:
        with self._lock:
            return self._entries.get(repair_id)
