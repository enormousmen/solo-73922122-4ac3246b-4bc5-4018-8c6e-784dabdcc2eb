# LoadBalancer Local 接流核查器

负载均衡器把请求发到某个节点却偶尔断流时，值班员可在网页上传同一批
**NodeList、单个 Service 和 EndpointSliceList 的 JSON 快照**，
查看每个**就绪节点**上各 **TCP 端口**在 `externalTrafficPolicy=Local` 下的接流状态。

## 判定范围与口径

| 主题 | 规则 |
| --- | --- |
| 服务前提 | 仅支持 `type=LoadBalancer` 且 `externalTrafficPolicy=Local` 的 Service；否则整次核查报错 |
| 协议/地址 | 仅看 TCP 端口与 IPv4 后端地址；UDP/SCTP 端口、IPv6/FQDN 端点忽略 |
| 切片关联 | 按**命名空间** + 标签 `kubernetes.io/service-name=<服务名>` 关联 EndpointSlice，再按端口名/目标端口匹配 |
| 节点范围 | 只评估 `Ready=True` 的节点；未就绪节点列出为跳过项，其后端不参与判定 |
| 后端身份 | 同一端口下，**后端 IP + 目标端口**相同的切片记录视为同一后端（多条记录合并） |
| 可接流 `accept` | 该节点该端口存在 `conditions.ready=true` 的后端 |
| 仅终止兜底 `terminating_only` | 没有 ready 后端，但存在 `serving=true` 且 `terminating=true` 的后端 |
| 无可用后端 `unavailable` | 上述两类后端都没有 |
| 无法确认 `unconfirmed` | 不同切片记录对同一后端说法不一，且采用不同记录会改变本节点端口的结论；响应中列出冲突的 IP 与目标端口（及切片名、条件差异） |

Local 策略下只看**本节点**的后端：别的节点上有 ready 后端不能帮本节点接流。
端点条件缺省（字段未出现）按 `false` 处理。

### 端口匹配细节

- Service 端口为**数字 `targetPort`**：按目标端口号匹配切片端口，与切片端口名无关。
- Service 端口为**字符串 `targetPort`**：按切片端口的 `name` 匹配；若同名端口在不同切片里
  解析出不同端口号，记为 `target_port_conflict`，当因此导致节点端口结论不一致时标 `unconfirmed`。

## 目录结构

```
app/
  models.py           # 快照解析与领域模型（Node / Service / EndpointSlice 记录）
  analyzer.py         # 切片关联、后端合并、三种结论与冲突判定
  main.py             # FastAPI 路由（multipart 与 JSON 两种调用方式 + 示例清单）
  static/index.html   # 单页前端（上传 → 核查 → 撤旧结果）
samples/              # 4 组可直接演示的快照（由脚本生成）
scripts/generate_samples.py
tests/test_analyzer.py # 34 个自测用例
Dockerfile / docker-compose.yml
```

## 用 Docker Compose 启动

```bash
docker compose up --build
# 打开 http://localhost:8000
```

网页支持上传三个 JSON 文件，也可在下拉框中**一键加载内置示例**并核查。

## 本地直接运行（无 Docker 时）

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## HTTP 接口

- `POST /api/analyze`（multipart：`node_list`、`service`、`endpoint_slice_list`）
- `POST /api/analyze-json`（JSON 体：`{node_list, service, endpoint_slice_list}`），适合脚本
- `GET /api/samples`：内置示例清单（网页演示用）
- `GET /healthz`

curl 示例：

```bash
curl -s \
  -F "node_list=@samples/conflict/nodes.json" \
  -F "service=@samples/conflict/service.json" \
  -F "endpoint_slice_list=@samples/conflict/endpoint-slices.json" \
  http://localhost:8000/api/analyze
```

## 示例快照

重新生成：`python3 scripts/generate_samples.py samples`

| 场景 | 目录 | 预期结果 |
| --- | --- | --- |
| 正常接流 | `samples/accept/` | node-a 两个端口均有 ready 后端可接流；node-b 的 http 仅终止兜底、metrics 无可用后端；node-c 未就绪被跳过 |
| 仅终止兜底 | `samples/terminating-only/` | 两个就绪节点的两个端口都只有 serving+terminating 后端 |
| 无可用后端 | `samples/unavailable/` | node-b 两个端口的后端均不可用；node-a 正常可接流 |
| 记录冲突 | `samples/conflict/` | node-a/http 同一后端 `10.0.1.41:8080` 在两份切片中条件冲突 → 无法确认；metrics 端口名解析出 9101/9102 两个目标端口 → 无法确认，并列出冲突 IP/端口 |

## 自测

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -v
```

## 已知边界（未实现/刻意不支持）

- 仅支持 IPv4；IPv6 地址与 FQDN 端点不参与判定
- 仅评估 TCP 端口，UDP/SCTP 直接忽略
- 不支持非 LoadBalancer 或 `externalTrafficPolicy=Cluster` 的 Service，遇到即报错并由前端撤下旧结果
- 不模拟 kube-proxy 的实际转发行为、健康检查节点门控（`healthcheckNodePort`）与防火墙规则，只按 EndpointSlice 快照做静态判定
- 切片端点 `targetRef`、拓扑路由、双栈（`dualStack`）等字段不参与判定
