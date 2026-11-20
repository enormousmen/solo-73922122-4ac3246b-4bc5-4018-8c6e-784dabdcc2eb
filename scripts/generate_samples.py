"""生成接流核查器的演示快照。

用法：python3 scripts/generate_samples.py [输出目录，默认 samples]

四个场景均为同一批 NodeList（含一个 NotReady 节点）+ 同一个
LoadBalancer / externalTrafficPolicy=Local Service（http、metrics 两个 TCP 端口），
差别只在 EndpointSliceList：

  accept/                 就绪节点上有 ready 后端；另一个节点仅终止兜底/无后端
  terminating-only/       全部就绪节点都没有 ready，只有 serving+terminating 后端
  unavailable/            某节点两个端口都没有可用后端
  conflict/               同一后端（IP+目标端口）在两份切片里条件冲突，且会改变结论；
                          另有端口名解析出不同目标端口的冲突
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

SERVICE_NAME = "web-lb"
NAMESPACE = "shop"
NODE_NAMES = ["node-a", "node-b", "node-c"]  # node-c 为 NotReady


def node_list() -> dict:
    return {
        "apiVersion": "v1",
        "kind": "NodeList",
        "items": [
            {
                "apiVersion": "v1",
                "kind": "Node",
                "metadata": {"name": name},
                "status": {
                    "conditions": [
                        {"type": "Ready", "status": "True" if name != "node-c" else "False"}
                    ]
                },
            }
            for name in NODE_NAMES
        ],
    }


def service() -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": SERVICE_NAME, "namespace": NAMESPACE},
        "spec": {
            "type": "LoadBalancer",
            "externalTrafficPolicy": "Local",
            "ports": [
                {"name": "http", "port": 80, "targetPort": 8080, "protocol": "TCP"},
                {"name": "metrics", "port": 9100, "targetPort": "metrics-port", "protocol": "TCP"},
            ],
        },
    }


def slice_(name: str, ports: list[dict], endpoints: list[dict]) -> dict:
    return {
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "labels": {"kubernetes.io/service-name": SERVICE_NAME},
        },
        "addressType": "IPv4",
        "ports": ports,
        "endpoints": endpoints,
    }


def endpoint(ip: str, node: str, *, ready=None, serving=None, terminating=None) -> dict:
    conditions = {}
    if ready is not None:
        conditions["ready"] = ready
    if serving is not None:
        conditions["serving"] = serving
    if terminating is not None:
        conditions["terminating"] = terminating
    return {
        "addresses": [ip],
        "nodeName": node,
        "conditions": conditions,
    }


HTTP_PORTS = [{"name": "http", "port": 8080, "protocol": "TCP"}]
METRICS_PORTS = [{"name": "metrics-port", "port": 9101, "protocol": "TCP"}]


def build_accept() -> dict:
    # node-a：http 有 ready；node-b：http 仅终止兜底；metrics node-a ready、node-b 无后端
    return {"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSliceList", "items": [
        slice_("web-lb-http-1", HTTP_PORTS, [
            endpoint("10.0.1.11", "node-a", ready=True, serving=True, terminating=False),
            endpoint("10.0.1.12", "node-a", ready=True, serving=True, terminating=False),
            endpoint("10.0.2.11", "node-b", ready=False, serving=True, terminating=True),
        ]),
        slice_("web-lb-metrics-1", METRICS_PORTS, [
            endpoint("10.0.1.11", "node-a", ready=True, serving=True, terminating=False),
        ]),
    ]}


def build_terminating_only() -> dict:
    # 两个就绪节点的两个端口都只有 serving+terminating 后端
    return {"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSliceList", "items": [
        slice_("web-lb-http-term", HTTP_PORTS, [
            endpoint("10.0.1.21", "node-a", ready=False, serving=True, terminating=True),
            endpoint("10.0.2.21", "node-b", ready=False, serving=True, terminating=True),
        ]),
        slice_("web-lb-metrics-term", METRICS_PORTS, [
            endpoint("10.0.1.21", "node-a", ready=False, serving=True, terminating=True),
            endpoint("10.0.2.21", "node-b", ready=False, serving=True, terminating=True),
        ]),
    ]}


def build_unavailable() -> dict:
    # node-a：http ready 可接流；node-b：两个端口都无可用后端（端点 ready=False 且未在 serving）
    return {"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSliceList", "items": [
        slice_("web-lb-http-down", HTTP_PORTS, [
            endpoint("10.0.1.31", "node-a", ready=True, serving=True, terminating=False),
            endpoint("10.0.2.31", "node-b", ready=False, serving=False, terminating=False),
        ]),
        slice_("web-lb-metrics-down", METRICS_PORTS, [
            endpoint("10.0.1.31", "node-a", ready=True, serving=True, terminating=False),
            endpoint("10.0.2.31", "node-b", ready=False, serving=False, terminating=True),
        ]),
    ]}


def build_conflict() -> dict:
    # 冲突 1：同一后端 10.0.1.41:8080 在两份切片里条件不一致
    #   （一份 ready=True，一份 ready=False/serving=True/terminating=True），
    #   采用不同记录会让 node-a/http 在「可接流」与「仅终止兜底」间摇摆 → 无法确认。
    # 冲突 2：字符串 targetPort 端口名 metrics-port 在两份切片里分别解析为
    #   9101 / 9102，且 node-b 仅在 9102 上有 ready 后端 → 无法确认。
    return {"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSliceList", "items": [
        slice_("web-lb-http-a", HTTP_PORTS, [
            endpoint("10.0.1.41", "node-a", ready=True, serving=True, terminating=False),
            endpoint("10.0.2.41", "node-b", ready=True, serving=True, terminating=False),
        ]),
        slice_("web-lb-http-b", HTTP_PORTS, [
            endpoint("10.0.1.41", "node-a", ready=False, serving=True, terminating=True),
        ]),
        slice_("web-lb-metrics-a", [{"name": "metrics-port", "port": 9101, "protocol": "TCP"}], [
            endpoint("10.0.1.41", "node-a", ready=True, serving=True, terminating=False),
        ]),
        slice_("web-lb-metrics-b", [{"name": "metrics-port", "port": 9102, "protocol": "TCP"}], [
            endpoint("10.0.2.41", "node-b", ready=True, serving=True, terminating=False),
        ]),
    ]}


SCENARIOS = {
    "accept": build_accept,
    "terminating-only": build_terminating_only,
    "unavailable": build_unavailable,
    "conflict": build_conflict,
}


def main(out_dir: str) -> None:
    root = Path(out_dir)
    for scenario, builder in SCENARIOS.items():
        path = root / scenario
        path.mkdir(parents=True, exist_ok=True)
        (path / "nodes.json").write_text(
            json.dumps(node_list(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (path / "service.json").write_text(
            json.dumps(service(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (path / "endpoint-slices.json").write_text(
            json.dumps(builder(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {path}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "samples")
