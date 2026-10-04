"""补帧试算：在不改写来源冻结捕获的前提下，裁决一组补帧能否补齐事务。

来源只能由其审计标识引用（其原始捕获已冻结）。试算把补帧严格追加到来源
捕获末尾，用与常规审计完全相同的 Auditor 重新裁决：

  * 来源裁决非 incomplete（closed_ok / violation）→ 不视为可修复试算，
    新裁决仍照常算出（闭环后追加必然违规等），来源冻结结论绝不改变；
  * 补帧不能消除原缺口 → 新裁决仍为 incomplete（附剩余缺失区间）；
  * 补帧首帧在来源当前阶段不合法 / 仍产生协议违约 → 新裁决为 violation，
    first_violation 的 index 为追加后序列中的全局序号。
"""

from __future__ import annotations

from . import audit as audit_mod
from .store import FrozenEntry


def _source_summary(entry: FrozenEntry) -> dict:
    """来源审计的冻结摘要（只读引用，不回写来源条目）。"""
    v = entry.verdict
    return {
        "audit_id": entry.audit_id,
        "verdict": v.get("verdict"),
        "phase": v.get("phase"),
        "pdu_count": entry.pdu_count,
        "frozen_at": v.get("frozen_at"),
        "frozen": v.get("frozen"),
    }


def build_repair_result(source: FrozenEntry,
                        patch_frames: list[bytes]) -> dict:
    """把补帧追加到来源冻结捕获末尾并重新裁决，组装试算结果。

    来源帧通过 source.frames 引用，绝不修改；新状态机只在追加序列上运行。
    """
    n = source.pdu_count
    auditor = audit_mod.Auditor()
    verdict = auditor.run(list(source.frames) + list(patch_frames),
                          source_pdu_count=n).to_dict()

    source_verdict = source.verdict.get("verdict")
    source_frozen = source.verdict.get("frozen") or {}
    original_missing = [list(r) for r in source_frozen.get("missing", [])]

    covered = [list(r) for r in auditor.supplement_coverage()]
    frozen_out = verdict.get("frozen") or {}
    remaining = [list(r) for r in frozen_out.get("missing", [])]
    # 补帧覆盖统计只含来源原本缺失的字节；剩余缺口为空即原缺口全部补回
    gaps_eliminated = bool(original_missing) and not remaining

    new_evidence = [dict(m) for m in verdict.get("phase_evidence", [])
                    if m["index"] >= n]

    fv = verdict.get("first_violation")
    fv_in_supplement = bool(fv) and fv["index"] >= n

    eligible = source_verdict == "incomplete"

    return {
        "source_audit_id": source.audit_id,
        "eligible": eligible,
        "ineligible_reason": None if eligible else
        "source_verdict_not_incomplete",
        "source": _source_summary(source),
        "original_missing": original_missing,
        "supplement": {
            "pdu_count": len(patch_frames),
            "first_pdu_index": n,
            # 补帧实际补回的字节（且为来源原缺口内的字节）区间
            "covered": covered,
            "remaining_missing": remaining,
            "gaps_eliminated": gaps_eliminated,
            "first_violation_in_supplement": fv_in_supplement,
            "violation_relative_index": fv["index"] - n
            if fv_in_supplement else None,
            # 补帧阶段新产生的双方阶段证据（NAK/重传/ACK/Finished…）
            "new_phase_evidence": new_evidence,
        },
        "verdict": verdict,
    }
