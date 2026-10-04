"""缺段修复试算：不改写原捕获，把补帧严格追加到已冻结捕获末尾重新裁决。

仅当来源审计冻结为 incomplete 且合并捕获按既有规则裁决为 closed_ok 时，
修复视为成功（accepted=true）。其余情形均返回新的修复裁决，来源冻结结论
不受影响：
  source_not_incomplete — 来源并非 incomplete
  gap_remaining         — 补帧不能消除原缺口（合并裁决仍 incomplete）
  first_frame_rejected  — 补帧首帧在当前阶段不合法（首违规即补帧首帧）
  protocol_violation    — 补帧仍产生协议违约（首违规在后续补帧上）

成功结果同时给出：来源审计标识、原有缺失区间、补帧新覆盖的区间以及合并
捕获的闭环阶段证据，便于确认 NAK 请求的字节确实已被补回。
"""

from __future__ import annotations

from . import audit as audit_mod
from .store import FrozenEntry

# 修复拒绝原因
RJ_SOURCE_NOT_INCOMPLETE = "source_not_incomplete"
RJ_GAP_REMAINING = "gap_remaining"
RJ_FIRST_FRAME_REJECTED = "first_frame_rejected"
RJ_PROTOCOL_VIOLATION = "protocol_violation"


def subtract_ranges(combined: list[tuple[int, int]],
                    base: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """返回 combined 中未被 base 覆盖的区间（输入均为排序不重叠 [s,e)）。"""
    out: list[tuple[int, int]] = []
    for cs, ce in combined:
        parts = [(cs, ce)]
        for bs, be in base:
            nxt: list[tuple[int, int]] = []
            for s, e in parts:
                if be <= s or bs >= e:
                    nxt.append((s, e))
                    continue
                if bs > s:
                    nxt.append((s, bs))
                if be < e:
                    nxt.append((be, e))
            parts = nxt
        out.extend(parts)
    return out


def adjudicate(source: FrozenEntry, repair_frames: list[bytes]) -> dict:
    """把补帧追加到来源冻结捕获末尾，按既有审计规则重新裁决。"""
    source_verdict = source.verdict
    src_frozen = source_verdict.get("frozen") or {}
    source_missing = src_frozen.get("missing") or []
    source_coverage = src_frozen.get("coverage") or []

    combined = list(source.frames) + list(repair_frames)
    verdict = audit_mod.Auditor().run(combined).to_dict()

    # 补帧新覆盖的区间 = 合并覆盖 − 来源覆盖（追加处理只会扩大覆盖）
    repair_coverage = subtract_ranges(
        [tuple(r) for r in (verdict["frozen"].get("coverage") or [])],
        [tuple(r) for r in source_coverage],
    )

    sv = source_verdict.get("verdict")
    cv = verdict.get("verdict")
    accepted = False
    reject = None
    if sv != "incomplete":
        reject = RJ_SOURCE_NOT_INCOMPLETE
    elif cv == "closed_ok":
        accepted = True
    elif cv == "incomplete":
        reject = RJ_GAP_REMAINING
    elif cv == "violation":
        fv = verdict.get("first_violation") or {}
        # 来源为 incomplete，原捕获内不可能有违规；首违规必落在补帧上
        if fv.get("index") == len(source.frames):
            reject = RJ_FIRST_FRAME_REJECTED
        else:
            reject = RJ_PROTOCOL_VIOLATION

    return {
        "source_audit_id": source.audit_id,
        "source_verdict": sv,
        "source_missing": source_missing,
        "repair_coverage": [[s, e] for s, e in repair_coverage],
        "repair_pdu_count": len(repair_frames),
        "combined_pdu_count": len(combined),
        "accepted": accepted,
        "reject_reason": reject,
        "verdict": verdict,
    }
