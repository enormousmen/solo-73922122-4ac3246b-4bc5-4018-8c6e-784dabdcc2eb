"""接流核查器自测：解析、逐节点端口判定、记录冲突与 HTTP 接口。"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.analyzer import (
    STATUS_ACCEPT,
    STATUS_TERMINATING_ONLY,
    STATUS_UNAVAILABLE,
    STATUS_UNCONFIRMED,
    analyze,
)
from app.main import app
from app.models import (
    SnapshotError,
    iter_slice_records,
    parse_endpoint_slices,
    parse_nodes,
    parse_service,
)

client = TestClient(app)


# --------------------------------------------------------------------------- #
# 构造夹具
# --------------------------------------------------------------------------- #
def make_nodes(specs):
    return {
        "apiVersion": "v1", "kind": "NodeList",
        "items": [
            {"kind": "Node", "metadata": {"name": name},
             "status": {"conditions": [{"type": "Ready", "status": "True" if ready else "False"}]}}
            for name, ready in specs
        ],
    }


def make_service(ports=None, policy="Local", svc_type="LoadBalancer",
                 name="web", namespace="shop"):
    ports = ports or [
        {"name": "http", "port": 80, "targetPort": 8080, "protocol": "TCP"},
    ]
    return {
        "kind": "Service",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"type": svc_type, "externalTrafficPolicy": policy, "ports": ports},
    }


def make_slice(name, ports, endpoints, namespace="shop", service_name="web",
               address_type="IPv4"):
    return {
        "kind": "EndpointSlice",
        "addressType": address_type,
        "metadata": {
            "name": name, "namespace": namespace,
            "labels": {"kubernetes.io/service-name": service_name},
        },
        "ports": ports,
        "endpoints": endpoints,
    }


def make_endpoint(ip, node, ready=None, serving=None, terminating=None):
    conditions = {}
    for key, value in (("ready", ready), ("serving", serving), ("terminating", terminating)):
        if value is not None:
            conditions[key] = value
    return {"addresses": [ip], "nodeName": node, "conditions": conditions}


def make_slice_list(*slices):
    return {"kind": "EndpointSliceList", "items": list(slices)}


HTTP_PORT = [{"name": "http", "port": 8080, "protocol": "TCP"}]


def run(nodes, service, slices):
    return analyze(
        parse_nodes(nodes),
        parse_service(service),
        parse_endpoint_slices(slices),
    )


def status_map(result):
    return {(np.node, np.port_name): np.status for np in result.node_ports}


# --------------------------------------------------------------------------- #
# 解析与前提校验
# --------------------------------------------------------------------------- #
def test_parse_nodes_ready_and_duplicate():
    nodes = parse_nodes(make_nodes([("a", True), ("b", False)]))
    assert [(n.name, n.ready) for n in nodes] == [("a", True), ("b", False)]
    payload = make_nodes([("a", True)])
    payload["items"].append(payload["items"][0])
    with pytest.raises(SnapshotError):
        parse_nodes(payload)


def test_parse_nodes_rejects_non_list():
    with pytest.raises(SnapshotError):
        parse_nodes({"kind": "Node"})
    with pytest.raises(SnapshotError):
        parse_nodes({"kind": "NodeList", "items": []})


def test_service_requires_loadbalancer():
    with pytest.raises(SnapshotError, match="LoadBalancer"):
        parse_service(make_service(svc_type="ClusterIP"))


def test_service_requires_local_policy():
    with pytest.raises(SnapshotError, match="Local"):
        parse_service(make_service(policy="Cluster"))


def test_service_rejects_list_and_unnamed_tcp_port():
    with pytest.raises(SnapshotError, match="单个 Service"):
        parse_service({"kind": "ServiceList", "items": []})
    bad_ports = [{"port": 80, "targetPort": 8080, "protocol": "TCP"}]
    with pytest.raises(SnapshotError, match="name"):
        parse_service(make_service(ports=bad_ports))


def test_service_udp_ports_skipped_and_tcp_required():
    only_udp = [{"name": "dns", "port": 53, "targetPort": 5353, "protocol": "UDP"}]
    with pytest.raises(SnapshotError, match="TCP"):
        parse_service(make_service(ports=only_udp))
    mixed = only_udp + [{"name": "http", "port": 80, "targetPort": 8080, "protocol": "TCP"}]
    info = parse_service(make_service(ports=mixed))
    assert [p.name for p in info.ports] == ["http"]


def test_service_string_target_port():
    svc = make_service(ports=[{"name": "metrics", "port": 9100,
                               "targetPort": "metrics-port", "protocol": "TCP"}])
    info = parse_service(svc)
    assert info.ports[0].target_port is None
    assert info.ports[0].target_port_name == "metrics-port"


def test_endpoint_slice_validation():
    with pytest.raises(SnapshotError):
        parse_endpoint_slices({"kind": "EndpointSliceList", "items": []})
    dup = make_slice_list(make_slice("s1", HTTP_PORT, []), make_slice("s1", HTTP_PORT, []))
    with pytest.raises(SnapshotError, match="重复"):
        parse_endpoint_slices(dup)


def test_records_skip_ipv6_and_udp_and_bad_ports():
    slices = [make_slice("s1", [
        {"name": "http", "port": 8080, "protocol": "TCP"},
        {"name": "dns", "port": 5353, "protocol": "UDP"},
        {"name": "bad", "port": 0, "protocol": "TCP"},
    ], [
        make_endpoint("fd00::1", "node-a", ready=True),
        make_endpoint("10.0.0.1", "node-a", ready=True),
    ])]
    records = iter_slice_records(slices)
    assert len(records) == 1
    assert records[0].address == "10.0.0.1"
    assert records[0].target_port == 8080


# --------------------------------------------------------------------------- #
# 三种接流结论
# --------------------------------------------------------------------------- #
def test_accept_when_ready_backend_exists():
    nodes = make_nodes([("node-a", True)])
    slices = make_slice_list(make_slice("s1", HTTP_PORT, [
        make_endpoint("10.0.0.1", "node-a", ready=True, serving=True, terminating=False),
    ]))
    result = run(nodes, make_service(), slices)
    assert status_map(result) == {("node-a", "http"): STATUS_ACCEPT}
    np = result.node_ports[0]
    assert np.ready_backend_count == 1
    assert np.target_ports == [8080]


def test_terminating_only_without_ready():
    nodes = make_nodes([("node-a", True)])
    slices = make_slice_list(make_slice("s1", HTTP_PORT, [
        make_endpoint("10.0.0.2", "node-a", ready=False, serving=True, terminating=True),
    ]))
    result = run(nodes, make_service(), slices)
    np = result.node_ports[0]
    assert np.status == STATUS_TERMINATING_ONLY
    assert np.terminating_backend_count == 1


def test_unavailable_when_neither_ready_nor_serving_terminating():
    nodes = make_nodes([("node-a", True)])
    slices = make_slice_list(make_slice("s1", HTTP_PORT, [
        make_endpoint("10.0.0.3", "node-a", ready=False, serving=False, terminating=True),
    ]))
    result = run(nodes, make_service(), slices)
    assert result.node_ports[0].status == STATUS_UNAVAILABLE


def test_missing_conditions_default_to_false():
    nodes = make_nodes([("node-a", True)])
    slices = make_slice_list(make_slice("s1", HTTP_PORT, [
        {"addresses": ["10.0.0.4"], "nodeName": "node-a", "conditions": {}},
    ]))
    result = run(nodes, make_service(), slices)
    assert result.node_ports[0].status == STATUS_UNAVAILABLE


def test_serving_without_terminating_is_not_fallback():
    nodes = make_nodes([("node-a", True)])
    slices = make_slice_list(make_slice("s1", HTTP_PORT, [
        make_endpoint("10.0.0.5", "node-a", ready=False, serving=True, terminating=False),
    ]))
    result = run(nodes, make_service(), slices)
    assert result.node_ports[0].status == STATUS_UNAVAILABLE


def test_ready_backend_on_same_node_wins_over_terminating():
    nodes = make_nodes([("node-a", True)])
    slices = make_slice_list(make_slice("s1", HTTP_PORT, [
        make_endpoint("10.0.0.6", "node-a", ready=True, serving=True),
        make_endpoint("10.0.0.7", "node-a", ready=False, serving=True, terminating=True),
    ]))
    result = run(nodes, make_service(), slices)
    assert result.node_ports[0].status == STATUS_ACCEPT


def test_backends_on_other_nodes_are_not_considered():
    # node-a 自己没有后端，node-b 的 ready 后端不能帮 node-a 接流（Local 策略）。
    nodes = make_nodes([("node-a", True), ("node-b", True)])
    slices = make_slice_list(make_slice("s1", HTTP_PORT, [
        make_endpoint("10.0.0.8", "node-b", ready=True, serving=True),
    ]))
    result = run(nodes, make_service(), slices)
    mapping = status_map(result)
    assert mapping[("node-a", "http")] == STATUS_UNAVAILABLE
    assert mapping[("node-b", "http")] == STATUS_ACCEPT


def test_not_ready_node_is_skipped():
    nodes = make_nodes([("node-a", True), ("node-c", False)])
    slices = make_slice_list(make_slice("s1", HTTP_PORT, [
        make_endpoint("10.0.0.9", "node-c", ready=True, serving=True),
    ]))
    result = run(nodes, make_service(), slices)
    assert result.ready_nodes == ["node-a"]
    assert result.skipped_nodes[0]["name"] == "node-c"
    assert {np.node for np in result.node_ports} == {"node-a"}


def test_duplicate_identical_records_merge_as_one_backend():
    nodes = make_nodes([("node-a", True)])
    slices = make_slice_list(
        make_slice("s1", HTTP_PORT, [
            make_endpoint("10.0.0.10", "node-a", ready=True, serving=True),
        ]),
        make_slice("s2", HTTP_PORT, [
            make_endpoint("10.0.0.10", "node-a", ready=True, serving=True),
        ]),
    )
    result = run(nodes, make_service(), slices)
    np = result.node_ports[0]
    assert np.status == STATUS_ACCEPT
    assert np.ready_backend_count == 1  # 同 IP+目标端口视为同一后端
    assert np.backends[0]["slice_names"] == ["s1", "s2"]
    assert np.conflicts == []


def test_same_ip_different_target_ports_are_distinct_backends():
    nodes = make_nodes([("node-a", True)])
    slices = make_slice_list(make_slice("s1", [
        {"name": "http", "port": 8080, "protocol": "TCP"},
        {"name": "http2", "port": 8081, "protocol": "TCP"},
    ], [
        make_endpoint("10.0.0.11", "node-a", ready=True, serving=True),
    ]))
    svc = make_service(ports=[
        {"name": "p1", "port": 80, "targetPort": 8080, "protocol": "TCP"},
        {"name": "p2", "port": 81, "targetPort": 8081, "protocol": "TCP"},
    ])
    result = run(nodes, svc, slices)
    for np in result.node_ports:
        assert np.status == STATUS_ACCEPT
        assert np.ready_backend_count == 1


def test_numeric_target_port_matches_by_port_number_ignoring_slice_port_name():
    nodes = make_nodes([("node-a", True)])
    slices = make_slice_list(make_slice("s1", [
        {"name": "totally-different-name", "port": 8080, "protocol": "TCP"},
    ], [
        make_endpoint("10.0.0.12", "node-a", ready=True, serving=True),
    ]))
    result = run(nodes, make_service(), slices)
    assert result.node_ports[0].status == STATUS_ACCEPT


def test_string_target_port_matches_by_slice_port_name():
    nodes = make_nodes([("node-a", True)])
    svc = make_service(ports=[{"name": "metrics", "port": 9100,
                               "targetPort": "metrics-port", "protocol": "TCP"}])
    slices = make_slice_list(make_slice("s1", [
        {"name": "metrics-port", "port": 9101, "protocol": "TCP"},
    ], [
        make_endpoint("10.0.0.13", "node-a", ready=True, serving=True),
    ]))
    result = run(nodes, svc, slices)
    assert result.node_ports[0].status == STATUS_ACCEPT
    assert result.node_ports[0].target_ports == [9101]


def test_no_matching_slice_yields_unavailable_with_note():
    nodes = make_nodes([("node-a", True)])
    other_ns = make_slice("s1", HTTP_PORT,
                          [make_endpoint("10.0.0.14", "node-a", ready=True)],
                          namespace="other")
    other_svc = make_slice("s2", HTTP_PORT,
                           [make_endpoint("10.0.0.14", "node-a", ready=True)],
                           service_name="other-service")
    result = run(nodes, make_service(), make_slice_list(other_ns, other_svc))
    np = result.node_ports[0]
    assert np.status == STATUS_UNAVAILABLE
    assert np.note and "EndpointSlice" in np.note
    assert result.diagnostics


# --------------------------------------------------------------------------- #
# 记录冲突 → 无法确认
# --------------------------------------------------------------------------- #
def test_conflicting_duplicate_backend_changes_conclusion():
    nodes = make_nodes([("node-a", True)])
    slices = make_slice_list(
        make_slice("s1", HTTP_PORT, [
            make_endpoint("10.0.0.20", "node-a", ready=True, serving=True, terminating=False),
        ]),
        make_slice("s2", HTTP_PORT, [
            make_endpoint("10.0.0.20", "node-a", ready=False, serving=True, terminating=True),
        ]),
    )
    result = run(nodes, make_service(), slices)
    np = result.node_ports[0]
    assert np.status == STATUS_UNCONFIRMED
    conflict = next(c for c in np.conflicts if c["type"] == "duplicate_backend_conflict")
    assert conflict["ip"] == "10.0.0.20"
    assert conflict["target_port"] == 8080
    assert set(conflict["slice_names"]) == {"s1", "s2"}


def test_conflict_that_does_not_change_conclusion_stays_accept():
    # 同后端两条记录都含 ready=True（另一条 terminating 标记差异不影响 ready 事实），
    # 结论恒为可接流，不应标无法确认。
    nodes = make_nodes([("node-a", True)])
    slices = make_slice_list(
        make_slice("s1", HTTP_PORT, [
            make_endpoint("10.0.0.21", "node-a", ready=True, serving=True, terminating=False),
        ]),
        make_slice("s2", HTTP_PORT, [
            make_endpoint("10.0.0.21", "node-a", ready=True, serving=True, terminating=True),
        ]),
    )
    result = run(nodes, make_service(), slices)
    np = result.node_ports[0]
    assert np.status == STATUS_ACCEPT
    assert np.backends[0]["ambiguous"] is True  # 记录仍有差异，保留可追溯明细


def test_conflict_between_unavailable_and_terminating_is_unconfirmed():
    nodes = make_nodes([("node-a", True)])
    slices = make_slice_list(
        make_slice("s1", HTTP_PORT, [
            make_endpoint("10.0.0.22", "node-a", ready=False, serving=True, terminating=True),
        ]),
        make_slice("s2", HTTP_PORT, [
            make_endpoint("10.0.0.22", "node-a", ready=False, serving=False, terminating=False),
        ]),
    )
    result = run(nodes, make_service(), slices)
    assert result.node_ports[0].status == STATUS_UNCONFIRMED


def test_second_ready_backend_keeps_accept_despite_conflict():
    # 冲突后端之外还有一个明确 ready 的后端，最坏口径下仍然可接流。
    nodes = make_nodes([("node-a", True)])
    slices = make_slice_list(
        make_slice("s1", HTTP_PORT, [
            make_endpoint("10.0.0.23", "node-a", ready=True, serving=True),
            make_endpoint("10.0.0.24", "node-a", ready=True, serving=True),
        ]),
        make_slice("s2", HTTP_PORT, [
            make_endpoint("10.0.0.23", "node-a", ready=False, serving=True, terminating=True),
        ]),
    )
    result = run(nodes, make_service(), slices)
    assert result.node_ports[0].status == STATUS_ACCEPT


def test_target_port_name_resolves_to_different_ports_conflict():
    nodes = make_nodes([("node-a", True), ("node-b", True)])
    svc = make_service(ports=[{"name": "metrics", "port": 9100,
                               "targetPort": "metrics-port", "protocol": "TCP"}])
    slices = make_slice_list(
        make_slice("s1", [{"name": "metrics-port", "port": 9101, "protocol": "TCP"}], [
            make_endpoint("10.0.0.30", "node-a", ready=True, serving=True),
        ]),
        make_slice("s2", [{"name": "metrics-port", "port": 9102, "protocol": "TCP"}], [
            make_endpoint("10.0.0.31", "node-b", ready=True, serving=True),
        ]),
    )
    result = run(nodes, svc, slices)
    for np in result.node_ports:
        assert np.status == STATUS_UNCONFIRMED
        assert any(c["type"] == "target_port_conflict" for c in np.conflicts)


def test_endpoints_on_unknown_node_are_ignored_with_diagnostic():
    nodes = make_nodes([("node-a", True)])
    slices = make_slice_list(make_slice("s1", HTTP_PORT, [
        make_endpoint("10.0.0.40", "node-ghost", ready=True, serving=True),
    ]))
    result = run(nodes, make_service(), slices)
    assert result.node_ports[0].status == STATUS_UNAVAILABLE
    assert any("node-ghost" in d for d in result.diagnostics)


# --------------------------------------------------------------------------- #
# HTTP 接口
# --------------------------------------------------------------------------- #
def _form_files(nodes, svc, slices):
    return {
        "node_list": ("nodes.json", json.dumps(nodes), "application/json"),
        "service": ("service.json", json.dumps(svc), "application/json"),
        "endpoint_slice_list": ("slices.json", json.dumps(slices), "application/json"),
    }


def test_healthz_and_index():
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/").status_code == 200


def test_api_analyze_multipart_accept():
    nodes = make_nodes([("node-a", True)])
    svc = make_service()
    slices = make_slice_list(make_slice("s1", HTTP_PORT, [
        make_endpoint("10.0.0.50", "node-a", ready=True, serving=True),
    ]))
    resp = client.post("/api/analyze", files=_form_files(nodes, svc, slices))
    assert resp.status_code == 200
    data = resp.json()
    assert data["node_ports"][0]["status"] == "accept"
    assert data["node_ports"][0]["status_label"] == "可接流"


def test_api_analyze_json_endpoint():
    nodes = make_nodes([("node-a", True)])
    svc = make_service()
    slices = make_slice_list(make_slice("s1", HTTP_PORT, [
        make_endpoint("10.0.0.51", "node-a", ready=False, serving=True, terminating=True),
    ]))
    resp = client.post("/api/analyze-json", json={
        "node_list": nodes, "service": svc, "endpoint_slice_list": slices,
    })
    assert resp.status_code == 200
    assert resp.json()["node_ports"][0]["status"] == "terminating_only"


def test_api_rejects_bad_policy_with_400():
    nodes = make_nodes([("node-a", True)])
    svc = make_service(policy="Cluster")
    slices = make_slice_list(make_slice("s1", HTTP_PORT, []))
    resp = client.post("/api/analyze", files=_form_files(nodes, svc, slices))
    assert resp.status_code == 400
    assert "Local" in resp.json()["detail"]


def test_api_rejects_missing_file_and_bad_json():
    resp = client.post("/api/analyze", files={
        "node_list": ("n.json", "{}", "application/json"),
        "service": ("s.json", "{}", "application/json"),
    })
    assert resp.status_code == 400
    resp2 = client.post("/api/analyze", files={
        "node_list": ("n.json", "{not-json", "application/json"),
        "service": ("s.json", "{}", "application/json"),
        "endpoint_slice_list": ("e.json", "{}", "application/json"),
    })
    assert resp2.status_code == 400
    assert "合法 JSON" in resp2.json()["detail"]


def test_samples_endpoint_lists_generated_scenarios():
    resp = client.get("/api/samples")
    ids = {s["id"] for s in resp.json()["scenarios"]}
    assert {"accept", "terminating-only", "unavailable", "conflict"} <= ids
