"""FastAPI 入口：上传 NodeList / Service / EndpointSliceList 快照，
查看每个就绪节点上各 TCP 端口在 externalTrafficPolicy=Local 下的接流状态。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .analyzer import analyze
from .models import (
    SnapshotError,
    parse_endpoint_slices,
    parse_nodes,
    parse_service,
)

app = FastAPI(title="LoadBalancer Local 接流核查器", version="1.0.0")

STATIC_DIR = Path(__file__).parent / "static"
SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"

STATUS_LABELS = {
    "accept": "可接流",
    "terminating_only": "仅终止兜底",
    "unavailable": "无可用后端",
    "unconfirmed": "无法确认",
}


def _load_json_bytes(data: bytes, label: str) -> Any:
    if not data:
        raise HTTPException(status_code=400, detail=f"{label} 内容为空")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"{label} 不是合法 JSON：{exc}") from exc


class AnalyzeRequest(BaseModel):
    node_list: Any
    service: Any
    endpoint_slice_list: Any


def _run_analysis(node_payload: Any, service_payload: Any, slice_payload: Any) -> dict:
    try:
        nodes = parse_nodes(node_payload)
        service = parse_service(service_payload)
        raw_slices = parse_endpoint_slices(slice_payload)
        result = analyze(nodes, service, raw_slices)
    except SnapshotError as exc:
        # 重查失败：返回 400，前端据此撤下旧结果并展示原因。
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _serialize(result)


def _serialize(result) -> dict:
    return {
        "namespace": result.namespace,
        "service": result.service,
        "external_traffic_policy": result.external_traffic_policy,
        "matched_slices": result.matched_slices,
        "ready_nodes": result.ready_nodes,
        "skipped_nodes": result.skipped_nodes,
        "diagnostics": result.diagnostics,
        "status_labels": STATUS_LABELS,
        "node_ports": [
            {
                "node": np.node,
                "port_name": np.port_name,
                "service_port": np.service_port,
                "target_ports": np.target_ports,
                "status": np.status,
                "status_label": STATUS_LABELS[np.status],
                "ready_backend_count": np.ready_backend_count,
                "terminating_backend_count": np.terminating_backend_count,
                "unavailable_backend_count": np.unavailable_backend_count,
                "backends": np.backends,
                "conflicts": np.conflicts,
                "note": np.note,
            }
            for np in result.node_ports
        ],
    }


@app.post("/api/analyze")
async def analyze_uploads(
    node_list: UploadFile | None = File(default=None),
    service: UploadFile | None = File(default=None),
    endpoint_slice_list: UploadFile | None = File(default=None),
):
    if node_list is None or service is None or endpoint_slice_list is None:
        raise HTTPException(
            status_code=400,
            detail="需要上传 node_list、service、endpoint_slice_list 三个 JSON 文件",
        )
    node_payload = _load_json_bytes(await node_list.read(), "NodeList")
    service_payload = _load_json_bytes(await service.read(), "Service")
    slice_payload = _load_json_bytes(await endpoint_slice_list.read(), "EndpointSliceList")
    return _run_analysis(node_payload, service_payload, slice_payload)


@app.post("/api/analyze-json")
async def analyze_json(req: AnalyzeRequest):
    """供脚本/curl 直接以 JSON 体调用。"""
    return _run_analysis(req.node_list, req.service, req.endpoint_slice_list)


@app.get("/api/samples")
async def list_samples():
    """列出内置示例快照，供网页一键加载演示。"""
    scenarios: list[dict] = []
    if not SAMPLES_DIR.is_dir():
        return {"scenarios": scenarios}
    for scenario_dir in sorted(p for p in SAMPLES_DIR.iterdir() if p.is_dir()):
        files = {
            "node_list": scenario_dir / "nodes.json",
            "service": scenario_dir / "service.json",
            "endpoint_slice_list": scenario_dir / "endpoint-slices.json",
        }
        if all(path.is_file() for path in files.values()):
            scenarios.append({
                "id": scenario_dir.name,
                "name": scenario_dir.name,
                "files": {key: f"/samples/{scenario_dir.name}/{path.name}"
                          for key, path in files.items()},
            })
    return {"scenarios": scenarios}


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
# 内置示例只读挂载，供网页拉取演示数据。
app.mount("/samples", StaticFiles(directory=SAMPLES_DIR), name="samples")
