#!/bin/sh
# 一次性验收：构建检查 → 服务健康 → HTTP 冒烟完整闭环 → 缺段修复/冲突重传代码测试。
# 任一环节失败立即以非零退出码结束（compose 通过 --exit-code-from verify 上报）。
set -eu

BASE_URL="${WEB_BASE_URL:-http://web:8080}"

echo "[verify] (1/4) 构建检查：编译全部 Python 源并导入服务模块"
python3 -m compileall -q app smoke.py
python3 -c "import app.server, app.audit, app.cfdp, app.store, app.repair"

echo "[verify] (2/4) 等待审计服务健康: ${BASE_URL}"
python3 - "${BASE_URL}" <<'PY'
import sys, time, json, urllib.request
base = sys.argv[1]
deadline = time.time() + 30
last = None
while time.time() < deadline:
    try:
        with urllib.request.urlopen(base + "/healthz", timeout=3) as r:
            if r.status == 200:
                print("[verify] 服务健康：", json.loads(r.read())["status"])
                sys.exit(0)
    except OSError as exc:
        last = exc
    time.sleep(0.5)
print("[verify] 服务未在超时内就绪:", last)
sys.exit(1)
PY

echo "[verify] (3/4) HTTP 冒烟：完整闭环 + 缺段修复试算"
python3 smoke.py "${BASE_URL}"

echo "[verify] (4/4) 代码测试：缺段修复（精确 NAK 区间）、冲突重传（首违规定位）与修复试算"
# 完整套件即包含缺段修复 TestMissingSegmentRepair 与冲突重传
# TestViolations.test_conflicting_retransmit 及对应 HTTP 用例。
python3 -m unittest discover -s tests -v

echo "[verify] ALL ACCEPTANCE CHECKS PASSED"
