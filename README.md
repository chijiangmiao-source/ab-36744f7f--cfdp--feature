# CFDP Class 2 事务闭环审计器

深空探测器回传文件时，链路重传或丢段可能让**表面完成**的 CFDP Class 2
事务实际缺少字节。本服务在归档入库前复核捕获是否**真正闭环**：审计员按
捕获顺序提交同一事务双向的 Base64 CFDP PDU，读取冻结的文件长度、
CRC32C、覆盖区间、阶段证据，或首个违约 PDU 的精确位置与当时阶段。

## 能力边界（仅处理该子集）

- 短头（8 字节）、**16 位实体 ID 与事务号**；
- acknowledged mode（Class 2）的六类 PDU：
  Metadata、File Data、EOF、ACK、NAK、Finished；
- 文件 ≤ 64 KiB（文件长度 / 偏移 / NAK 边界为 u32，可表达到 65536）；
- 每帧尾部 4 字节 **CRC32C（Castagnoli）**，校验失败即判该帧畸形。

固定头布局：

```
byte0  version(3)=001 | pdu_type(3) | direction(1) | crc_flag(1)
byte1  类型相关标志（Finished: condition/delivery/status）
2..3   源实体 ID (u16 BE)
4..5   事务序号 (u16 BE)
6..7   data field 长度 (u16 BE)
[8..]  data field，crc_flag=1 时末尾追加 4 字节 CRC32C（覆盖头+data）
```

## 审计规则

1. 全部 PDU 必须属于同一 `(实体, 事务号)`，方向位须与类型匹配
   （Metadata/FileData/EOF 下行，ACK/NAK/Finished 上行）；
2. 事务必须以 Metadata 起始且仅一次；EOF 长度须与 Metadata 一致；
3. File Data 可重传，**重叠字节必须逐字节一致**，否则定位首个冲突偏移；
4. **EOF 后若存在未覆盖区间，必须先收到由未覆盖区间（合并后）精确相等
   生成的 NAK**，禁止跳过 NAK 直接补齐，也禁止发多余/部分 NAK；
5. 全覆盖且重算 CRC32C 与 EOF 携带值相符后，才允许
   `ACK(EOF, complete)`；
6. 随后 `Finished(complete,noerror)` → `ACK(Finished,complete)` 闭环；
7. 终态后再写入任何 PDU：给出首个违规 PDU、当时阶段（`closed`）并
   **撤销旧成功结论**（裁决中 `reached_closed_before_violation=true`）；
8. 错误事务关联、过早确认、错误 ACK 类型、错误 ACK/Finished 状态等
   同样给出**首个违规 PDU 序号、阶段、原因、期望/实际**。

裁决三种：

| verdict | 含义 |
|---|---|
| `closed_ok` | 闭环通过、完整覆盖、CRC 相符、双方阶段证据齐备 |
| `incomplete` | 捕获在闭环前终止；附覆盖/缺失区间、首个缺口偏移、当前阶段 |
| `violation` | 出现首个违规 PDU；附 `index/phase/reason/detail/expected/actual` |

## 冻结语义

- 相同 `audit_id` + **完全相同捕获**（帧顺序与原始字节逐字节一致，
  含方向位）→ 返回**原冻结裁决**（`result=replayed`，200）；
- 相同 `audit_id` 但**任一方向或原始 PDU 改变** → `409 conflict`；
- 新标识 → `201 frozen`。裁决可随时 `GET /audit/{id}` 读取。

## HTTP API

```
GET  /healthz                 健康响应
POST /audit                   {"audit_id":"...","capture":["<b64>",...]}
GET  /audit/{audit_id}        读取冻结裁决
```

`verdict.frozen` 字段：`file_length`、`received_length`、`crc32c`、
`checksum_mismatch`、`coverage`、`missing`、`first_missing_offset`；
`verdict.phase_evidence` 为双方阶段证据（role/pdu/stage 序列）。

## 本地运行（仅需 Python 3.11+，无第三方依赖）

```bash
python3 -m app.server                       # 默认 0.0.0.0:8080
CFDP_AUDIT_PORT=9090 python3 -m app.server  # 自定义端口
python3 -m unittest discover -s tests       # 49 个测试
python3 smoke.py http://127.0.0.1:8080      # HTTP 完整闭环冒烟
```

## Compose 编排与一次性验收

`web` 为常驻服务，宿主端口可用 `WEB_PORT` 配置（默认 8080）；
`verify` 是**执行后退出的一次性验收服务**，在同一编排中：

1. 构建检查（编译并导入全部模块）；
2. 等待 `web` 健康；
3. 以 HTTP 冒烟提交一个完整闭环（并校验回放返回原冻结裁决）；
4. 运行代码测试（缺段修复的精确 NAK 区间、冲突重传首违规定位等）。

```bash
# 验收：verify 退出码即验收结果（0 通过）
WEB_PORT=8080 docker compose up --build --abort-on-container-exit \
    --exit-code-from verify

# 仅启动服务
docker compose up --build web
```

## 目录

```
app/cfdp.py    PDU 编解码 + CRC32C
app/audit.py   Class 2 审计状态机与裁决
app/store.py   审计标识冻结/回放/冲突
app/server.py  HTTP 服务（标准库）
smoke.py       HTTP 完整闭环冒烟
verify.sh      一次性验收脚本（verify 容器入口）
tests/         49 个单元/HTTP 测试
```
